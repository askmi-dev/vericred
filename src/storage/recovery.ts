import { createReadStream, createWriteStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { lock } from 'proper-lockfile';

const FORMAT = 'vericred-offline-backup-v1';
const ephemeral = new Set(['preauth-codes.encrypted.json', 'access-tokens.encrypted.json',
  'credential-nonces.encrypted.json', 'admin-sessions.encrypted.json', 'csrf-tokens.encrypted.json', 'oid4vp_sessions.json']);
interface FileEntry { path: string; size: number; sha256: string; iv: string; tag: string; }
interface Manifest {
  format: typeof FORMAT; backupId: string; createdAt: string; files: FileEntry[];
  excludedFiles: string[]; localSourcePath?: string;
}
export interface BackupResult { backupId: string; files: number; excludedFiles: string[]; }
export interface RestoreResult { backupId: string; recoveryId: string; retiredLists: number; revokedCredentials: number; invalidatedFiles: string[]; }
function requireSecret(secret: string) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('Supply the existing PSEUDO_SECRET (at least 32 characters) separately');
}
function keyFor(secret: string, id: string, purpose: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, id, FORMAT + ':' + purpose, 32));
}
function safeRelative(path: string): boolean {
  return path.length > 0 && !isAbsolute(path) && !path.includes('\\') && !path.includes(':') &&
    path.split('/').every(part => part !== '' && part !== '.' && part !== '..');
}
function isWithin(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === '' || (!rel.startsWith('..' + sep) && rel !== '..' && !isAbsolute(rel));
}
async function exists(path: string) { try { await lstat(path); return true; } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error; } }
async function directory(path: string) {
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Expected a real directory, not a symlink');
  return realpath(path);
}
async function absentDestination(path: string, forbidden: string[]) {
  const parent = await directory(dirname(resolve(path)));
  const destination = join(parent, basename(resolve(path)));
  if (await exists(destination)) throw new Error('Destination already exists; refusing to overwrite');
  if (forbidden.some(root => isWithin(root, destination) || isWithin(destination, root))) throw new Error('Source and destination must be separate directories');
  return destination;
}
async function fileNames(root: string, prefix = ''): Promise<string[]> {
  const files: string[] = [];
  for (const item of await readdir(join(root, prefix), { withFileTypes: true })) {
    const name = prefix ? prefix + '/' + item.name : item.name;
    if (name === '.writer.lock') continue;
    if (!safeRelative(name) || item.isSymbolicLink()) throw new Error('Backup refuses symbolic links and unsafe paths');
    if (item.isDirectory()) files.push(...await fileNames(root, name));
    else if (item.isFile()) files.push(name);
    else throw new Error('Backup supports regular files only');
  }
  return files.sort();
}
function isSecretFile(name: string) { return basename(name) === 'secrets.json' || basename(name) === '.env' || basename(name).startsWith('.env.'); }
function authenticateStoredState(path: string, data: Buffer, secret: string) {
  const envelope = JSON.parse(data.toString('utf8'));
  const presentation = path === 'oid4vp_sessions.json';
  if (presentation && envelope.version !== 2) return; // Legacy state is discarded on restore.
  if (!presentation && envelope.version !== 1) throw new Error('Unsupported encrypted state format');
  const context = presentation ? 'vericred-presentation-store:' : 'vericred:' + basename(path).replace(/\.encrypted\.json$/, '') + ':';
  try {
    const decipher = createDecipheriv('aes-256-gcm', createHash('sha256').update(context + secret).digest(), Buffer.from(envelope.iv, 'hex'));
    decipher.setAuthTag(Buffer.from(envelope.tag, 'hex'));
    JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.content, 'hex')), decipher.final()]).toString('utf8'));
  } catch { throw new Error('PSEUDO_SECRET cannot authenticate existing encrypted state'); }
}
async function localSourcePath(source: string) {
  const config = JSON.parse(await readFile(join(source, 'vericred.config.json'), 'utf8'));
  if (!['json', 'manual', 'csv'].includes(config.dataSource?.type)) return undefined;
  const defaultPath = config.dataSource.type === 'manual' ? './data/manual_holders.json' :
    config.dataSource.type === 'csv' ? './data/holders.csv' : './data/holders.json';
  const path = resolve(config.dataSource.path ?? defaultPath);
  if (!isWithin(source, path)) throw new Error('Local holder source is outside DATA_DIR; relocate it into the volume before backup');
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error('Local holder source must be a regular file');
  return relative(source, path).split(sep).join('/');
}
async function encryptFile(source: string, target: string, path: string, key: Buffer): Promise<FileEntry> {
  const original = await lstat(source);
  if (!original.isFile() || original.isSymbolicLink()) throw new Error('Source file changed during backup');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from(path));
  const hash = createHash('sha256'); let size = 0;
  await pipeline(createReadStream(source), new Transform({ transform(chunk: Buffer, _encoding, done) {
    hash.update(chunk); size += chunk.length; done(null, chunk);
  } }), cipher, createWriteStream(target, { flags: 'wx', mode: 0o600 }));
  const final = await lstat(source);
  if (original.size !== final.size || original.mtimeMs !== final.mtimeMs || size !== final.size) throw new Error('Source changed during backup; stop all writers');
  return { path, size, sha256: hash.digest('hex'), iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex') };
}
/** Stop the issuer first. Takes its writer lease and produces an encrypted, authenticated snapshot. */
export async function backupData(sourcePath: string, backupPath: string, secret: string): Promise<BackupResult> {
  requireSecret(secret);
  const source = await directory(resolve(sourcePath));
  const destination = await absentDestination(backupPath, [source]);
  let compromised = false;
  const release = await lock(source, { lockfilePath: join(source, '.writer.lock'), stale: 30_000, update: 10_000, retries: 0,
    onCompromised: () => { compromised = true; } });
  let stage: string | undefined;
  try {
    const holderPath = await localSourcePath(source);
    await readFile(join(source, 'issuer-key.json'));
    const names = await fileNames(source);
    const excludedFiles = names.filter(isSecretFile);
    const included = names.filter(name => !isSecretFile(name));
    if (holderPath && !included.includes(holderPath)) throw new Error('Local holder source was excluded from backup');
    for (const path of included.filter(path => path.endsWith('.encrypted.json') || path === 'oid4vp_sessions.json')) {
      authenticateStoredState(path, await readFile(join(source, path)), secret);
    }
    stage = await mkdtemp(join(dirname(destination), '.vericred-backup-'));
    await mkdir(join(stage, 'files'), { mode: 0o700 });
    const manifest: Manifest = { format: FORMAT, backupId: randomUUID(), createdAt: new Date().toISOString(), files: [], excludedFiles, localSourcePath: holderPath };
    const key = keyFor(secret, manifest.backupId, 'files');
    for (const [index, path] of included.entries()) manifest.files.push(await encryptFile(join(source, path), join(stage, 'files', index + '.gcm'), path, key));
    if (compromised || JSON.stringify(await fileNames(source)) !== JSON.stringify(names)) throw new Error('Source changed or writer lease was lost during backup');
    const mac = createHmac('sha256', keyFor(secret, manifest.backupId, 'manifest')).update(JSON.stringify(manifest)).digest('hex');
    await writeFile(join(stage, 'manifest.json'), JSON.stringify({ manifest, mac }, null, 2), { flag: 'wx', mode: 0o600 });
    if (await exists(destination)) throw new Error('Destination appeared during backup; refusing to overwrite');
    await rename(stage, destination); stage = undefined;
    return { backupId: manifest.backupId, files: manifest.files.length, excludedFiles };
  } finally {
    try { if (stage) await rm(stage, { recursive: true, force: true }); } finally { await release(); }
  }
}
async function authenticatedManifest(backup: string, secret: string): Promise<Manifest> {
  const manifestPath = join(backup, 'manifest.json'); const info = await lstat(manifestPath);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 16 * 1024 * 1024) throw new Error('Invalid backup manifest');
  const envelope = JSON.parse(await readFile(manifestPath, 'utf8')); const manifest = envelope.manifest as Manifest;
  if (!manifest || manifest.format !== FORMAT || typeof manifest.backupId !== 'string' || !Array.isArray(manifest.files)) throw new Error('Unsupported backup format');
  const expected = createHmac('sha256', keyFor(secret, manifest.backupId, 'manifest')).update(JSON.stringify(manifest)).digest();
  const actual = typeof envelope.mac === 'string' ? Buffer.from(envelope.mac, 'hex') : Buffer.alloc(0);
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw new Error('Backup authentication failed: wrong PSEUDO_SECRET or modified manifest');
  const seen = new Set<string>();
  for (const entry of manifest.files) {
    if (typeof entry.path !== 'string' || !safeRelative(entry.path) || seen.has(entry.path) || entry.path === '.writer.lock' || isSecretFile(entry.path) ||
      !Number.isSafeInteger(entry.size) || entry.size < 0 || !/^[a-f0-9]{64}$/.test(entry.sha256) || !/^[a-f0-9]{24}$/.test(entry.iv) || !/^[a-f0-9]{32}$/.test(entry.tag)) throw new Error('Invalid backup file entry');
    seen.add(entry.path);
  }
  if (!seen.has('issuer-key.json') || !seen.has('vericred.config.json')) throw new Error('Backup is missing required issuer files');
  if (manifest.localSourcePath && (!safeRelative(manifest.localSourcePath) || !seen.has(manifest.localSourcePath))) throw new Error('Invalid local source path');
  return manifest;
}
async function decryptFile(source: string, target: string, entry: FileEntry, key: Buffer) {
  const info = await lstat(source);
  if (!info.isFile() || info.isSymbolicLink() || info.size !== entry.size) throw new Error('Missing or truncated backup file');
  const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(entry.iv, 'hex'));
  cipher.setAAD(Buffer.from(entry.path)); cipher.setAuthTag(Buffer.from(entry.tag, 'hex'));
  const hash = createHash('sha256'); await mkdir(dirname(target), { recursive: true, mode: 0o700 });
  try {
    await pipeline(createReadStream(source), cipher, new Transform({ transform(chunk: Buffer, _encoding, done) {
      hash.update(chunk); done(null, chunk);
    } }), createWriteStream(target, { flags: 'wx', mode: 0o600 }));
  } catch { throw new Error('Backup file authentication failed'); }
  if (hash.digest('hex') !== entry.sha256) throw new Error('Backup checksum mismatch');
}
function retireStatusLists(data: unknown, recoveredAt: string) {
  const store = data as { listId: string; listIds?: string[]; retiredListIds?: string[]; nextIndex: number;
    issuedCredentials: Array<{ listId?: string; revoked: boolean; revokedAt?: string; [key: string]: unknown }> };
  if (!store || typeof store.listId !== 'string' || !Array.isArray(store.issuedCredentials) ||
    (store.listIds && (!Array.isArray(store.listIds) || store.listIds.some(id => typeof id !== 'string'))) ||
    (store.retiredListIds && (!Array.isArray(store.retiredListIds) || store.retiredListIds.some(id => typeof id !== 'string')))) throw new Error('Invalid status registry; refusing unsafe recovery');
  const retired = new Set([store.listId, ...(store.listIds ?? []), ...(store.retiredListIds ?? [])]);
  for (const entry of store.issuedCredentials) {
    entry.listId ??= store.listId;
    if (typeof entry.listId !== 'string') throw new Error('Invalid status registry entry');
    retired.add(entry.listId); entry.revoked = true; entry.revokedAt ??= recoveredAt;
  }
  store.listId = randomUUID(); store.nextIndex = 0;
  store.retiredListIds = [...retired]; store.listIds = [...retired, store.listId];
  return store;
}
/** Restore to a new directory. Every pre-recovery list is wholly revoked; all temporary authorization is discarded. */
export async function restoreData(backupPath: string, targetPath: string, secret: string): Promise<RestoreResult> {
  requireSecret(secret);
  const backup = await directory(resolve(backupPath));
  const destination = await absentDestination(targetPath, [backup]);
  const manifest = await authenticatedManifest(backup, secret); await directory(join(backup, 'files'));
  let stage: string | undefined = await mkdtemp(join(dirname(destination), '.vericred-restore-'));
  try {
    const key = keyFor(secret, manifest.backupId, 'files');
    for (const [index, entry] of manifest.files.entries()) await decryptFile(join(backup, 'files', index + '.gcm'), join(stage, entry.path), entry, key);
    const invalidatedFiles = manifest.files.filter(entry => ephemeral.has(entry.path)).map(entry => entry.path);
    for (const path of invalidatedFiles) await rm(join(stage, path));
    const recoveredAt = new Date().toISOString(); const statusFile = join(stage, 'statuslist.json');
    const status = retireStatusLists(await exists(statusFile) ? JSON.parse(await readFile(statusFile, 'utf8')) :
      { listId: randomUUID(), listIds: [], nextIndex: 0, issuedCredentials: [] }, recoveredAt);
    await writeFile(statusFile, JSON.stringify(status), { mode: 0o600 });
    if (manifest.localSourcePath) {
      const configPath = join(stage, 'vericred.config.json'); const config = JSON.parse(await readFile(configPath, 'utf8'));
      config.dataSource.path = join(destination, manifest.localSourcePath);
      await writeFile(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
    }
    const result: RestoreResult = { backupId: manifest.backupId, recoveryId: randomUUID(), retiredLists: status.retiredListIds!.length,
      revokedCredentials: status.issuedCredentials.length, invalidatedFiles };
    await writeFile(join(stage, 'recovery.json'), JSON.stringify({ ...result, recoveredAt, policy: 'revoke-all-pre-recovery-lists', requiresCredentialReissuance: true }, null, 2), { mode: 0o600 });
    await writeFile(join(stage, 'audit.jsonl'), JSON.stringify({ timestamp: recoveredAt, event: 'storage.recovered', actor: 'offline-recovery', ...result }) + '\n', { flag: 'a', mode: 0o600 });
    if (await exists(destination)) throw new Error('Destination appeared during restore; refusing to overwrite');
    await rename(stage, destination); stage = undefined;
    return result;
  } finally { if (stage) await rm(stage, { recursive: true, force: true }); }
}