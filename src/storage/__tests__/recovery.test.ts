import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { createServer, type Server } from 'node:http';
import express from 'express';
import { jwtVerify } from 'jose';
import { backupData, restoreData } from '../recovery.js';
import { EncryptedMap } from '../encrypted-map.js';
import { acquireDataLease } from '../lease.js';
import { loadConfig } from '../../config/loader.js';
import { buildConnector } from '../../connectors/index.js';
import { getAllPublicKeys, getIssuerKeyPair, rotateIssuerKeyPair } from '../../keys/manager.js';
import { assignStatusIndex, revokeCredential, buildStatusListJWT, getIssuedCredentials, hasList, LIST_SIZE } from '../../revocation/statuslist.js';
import { createTokenRouter, issuePreAuthCode, lookupAccessToken } from '../../oid4vci/token.js';
import { createOid4vpRouter } from '../../oid4vp/router.js';
import { createSession, createCsrfToken } from '../../middleware/auth.js';
import '../../credentials/templates/age.js';

const fixtureParent = resolve('.validation-artifacts/recovery-tests');
const initialDataDir = process.env.DATA_DIR;
let fixture: string;
let source: string;
let backup: string;
let restored: string;
let server: Server | undefined;
const secret = process.env.PSEUDO_SECRET!;
function json(path: string) { return JSON.parse(readFileSync(path, 'utf8')); }
async function seed() {
  loadConfig();
  writeFileSync(join(source, 'holders.json'), JSON.stringify([{ id: 'holder-test', dateOfBirth: '1990-01-01' }]));
  await getIssuerKeyPair();
}
async function endpoints() {
  const app = express(); app.use(express.json()); app.use(createTokenRouter()); app.use(createOid4vpRouter());
  server = createServer(app);
  await new Promise<void>(done => server!.listen(0, '127.0.0.1', done));
  const address = server.address() as { port: number };
  return 'http://127.0.0.1:' + address.port;
}
const post = (body: unknown) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
beforeEach(async () => {
  mkdirSync(fixtureParent, { recursive: true }); fixture = mkdtempSync(join(fixtureParent, 'run-'));
  source = join(fixture, 'source'); backup = join(fixture, 'backup'); restored = join(fixture, 'restored');
  mkdirSync(source); process.env.DATA_DIR = source; await seed();
});
afterEach(async () => {
  if (server) { const active = server; server = undefined; await new Promise<void>((done, reject) => active.close(error => error ? reject(error) : done())); }
  process.env.DATA_DIR = initialDataDir;
  if (!fixture.startsWith(fixtureParent + '\\') && !fixture.startsWith(fixtureParent + '/')) throw new Error('Unsafe fixture cleanup path');
  rmSync(fixture, { recursive: true, force: true });
});
describe('offline backup and independent-directory restoration', () => {
  it('preserves keys and source, blocks rolled-back revocations and consumed grants, and allocates a new status generation', async () => {
    const firstKey = await getIssuerKeyPair(); const rotatedKey = await rotateIssuerKeyPair();
    const first = assignStatusIndex('before-backup', 'synthetic@example.invalid');
    const alreadyRevoked = assignStatusIndex('already-revoked', 'synthetic@example.invalid'); revokeCredential('already-revoked');
    const code = issuePreAuthCode({ id: 'holder-test', dateOfBirth: '1990-01-01' }, 'AgeCredential');
    const oldAccess = new EncryptedMap<any>('access-tokens'); oldAccess.set('old-access', { expiresAt: Date.now() + 600000 });
    new EncryptedMap<any>('credential-nonces').set('old-nonce', { expiresAt: Date.now() + 600000 });
    const adminSession = createSession(); createCsrfToken(adminSession);
    const base = await endpoints();
    const vpResponse = await fetch(base + '/api/oid4vp/initiate', post({ credentialType: 'AgeCredential' }));
    expect(vpResponse.status).toBe(200); const vp = await vpResponse.json() as { sessionId: string; readToken: string };
    writeFileSync(join(source, 'secrets.json'), JSON.stringify({ pseudonymSecret: secret, adminApiKey: process.env.ADMIN_API_KEY }));
    writeFileSync(join(source, '.env'), 'secret-file-marker');
    const originalPrivateKey = readFileSync(join(source, 'issuer-key.json'), 'utf8');
    const snapshot = await backupData(source, backup, secret);
    expect(snapshot.excludedFiles).toEqual(['.env', 'secrets.json']);
    expect(existsSync(join(source, '.writer.lock'))).toBe(false);
    const manifest = json(join(backup, 'manifest.json')).manifest;
    expect(manifest.files.some((f: { path: string }) => f.path === '.writer.lock')).toBe(false);
    const keyIndex = manifest.files.findIndex((f: { path: string }) => f.path === 'issuer-key.json');
    expect(readFileSync(join(backup, 'files', keyIndex + '.gcm'), 'utf8')).not.toContain(originalPrivateKey);
    // Real changes made after the snapshot are deliberately absent from it.
    revokeCredential('before-backup');
    const consumed = await fetch(base + '/token', post({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }));
    expect(consumed.status).toBe(200);
    const unseen = assignStatusIndex('after-backup', 'synthetic@example.invalid');
    const current = json(join(source, 'statuslist.json')); current.nextIndex = LIST_SIZE;
    writeFileSync(join(source, 'statuslist.json'), JSON.stringify(current));
    const unseenRollover = assignStatusIndex('unseen-new-list', 'synthetic@example.invalid');
    const sourceAfter = readFileSync(join(source, 'statuslist.json'), 'utf8');
    const result = await restoreData(backup, restored, secret);
    expect(result.invalidatedFiles).toHaveLength(6);
    expect(readFileSync(join(source, 'statuslist.json'), 'utf8')).toBe(sourceAfter);
    expect(readFileSync(join(restored, 'issuer-key.json'), 'utf8')).toBe(originalPrivateKey);
    expect(existsSync(join(restored, 'secrets.json'))).toBe(false);
    expect(existsSync(join(restored, '.env'))).toBe(false);
    expect(existsSync(join(restored, '.writer.lock'))).toBe(false);
    process.env.DATA_DIR = restored;
    expect((await getIssuerKeyPair()).kid).toBe(rotatedKey.kid);
    expect((await getAllPublicKeys()).map(k => k.kid).sort()).toEqual([firstKey.kid, rotatedKey.kid].sort());
    expect(loadConfig().dataSource.path).toBe(join(restored, 'holders.json'));
    expect(json(join(restored, 'holders.json'))[0].id).toBe('holder-test');
    expect(getIssuedCredentials().every(credential => credential.revoked)).toBe(true);
    expect(lookupAccessToken('old-access')).toBe(null);
    expect(new EncryptedMap('credential-nonces').has('old-nonce')).toBe(false);
    expect(new EncryptedMap('admin-sessions').has(adminSession)).toBe(false);
    const replay = await fetch(base + '/token', post({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }));
    expect(replay.status).toBe(400); expect(await replay.json()).toEqual({ error: 'invalid_grant' });
    expect((await fetch(base + '/api/oid4vp/session/' + vp.sessionId, { headers: { Authorization: 'Bearer ' + vp.readToken } })).status).toBe(401);
    const statusJWT = await buildStatusListJWT(first.listId);
    const { payload } = await jwtVerify(statusJWT, (await getIssuerKeyPair()).publicKey, { algorithms: ['ES256'] });
    const encoded = (payload.credentialSubject as { encodedList: string }).encodedList;
    const bytes = gunzipSync(Buffer.from(encoded, 'base64url'));
    // All indices revoked, including credentials issued after the snapshot.
    expect(bytes.every(byte => byte === 255)).toBe(true);
    expect(unseen.listId).toBe(first.listId); expect(alreadyRevoked.listId).toBe(first.listId);
    expect(hasList(unseenRollover.listId)).toBe(false);
    const next = assignStatusIndex('reissued', 'synthetic@example.invalid');
    expect(next.statusIndex).toBe(0); expect(next.listId).not.toBe(first.listId); expect(next.listId).not.toBe(unseenRollover.listId);
    // Recovered directory can acquire the normal single-writer lease independently.
    const release = await acquireDataLease(); await release();
    expect(json(join(restored, 'recovery.json')).requiresCredentialReissuance).toBe(true);
  });
  it.each([true, false])('restores the default manual registry when a JSON holder file exists: %s', async withJsonSource => {
    const manualSource = join(fixture, 'data'); mkdirSync(manualSource);
    const config = json(join(source, 'vericred.config.json')); config.dataSource = { type: 'manual' };
    writeFileSync(join(manualSource, 'vericred.config.json'), JSON.stringify(config));
    writeFileSync(join(manualSource, 'issuer-key.json'), readFileSync(join(source, 'issuer-key.json')));
    writeFileSync(join(manualSource, 'manual_holders.json'), JSON.stringify([{ id: 'manual-holder', dateOfBirth: '1992-01-01' }]));
    if (withJsonSource) writeFileSync(join(manualSource, 'holders.json'), JSON.stringify([{ id: 'json-holder', dateOfBirth: '2001-01-01' }]));
    // The omitted connector path is relative to its process working directory. Use a
    // separate process so the test cannot change the cwd of other tests or the app.
    const recoveryModule = pathToFileURL(resolve('src/storage/recovery.ts')).href;
    execFileSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
      'import { backupData, restoreData } from ' + JSON.stringify(recoveryModule) + ';' +
      'await backupData("data", "backup", process.env.PSEUDO_SECRET);' +
      'await restoreData("backup", "restored", process.env.PSEUDO_SECRET);'],
    { cwd: fixture, env: { ...process.env, DATA_DIR: manualSource }, timeout: 20_000, stdio: 'pipe' });
    expect(json(join(backup, 'manifest.json')).manifest.localSourcePath).toBe('manual_holders.json');
    process.env.DATA_DIR = restored;
    const recoveredConfig = loadConfig();
    expect(recoveredConfig.dataSource.path).toBe(join(restored, 'manual_holders.json'));
    const connector = buildConnector(recoveredConfig);
    expect(await connector.lookup('manual-holder')).toMatchObject({ id: 'manual-holder', dateOfBirth: '1992-01-01' });
    expect(await connector.lookup('json-holder')).toBeNull();
    expect(existsSync(join(restored, 'holders.json'))).toBe(withJsonSource);
    if (withJsonSource) expect(json(join(restored, 'holders.json'))[0].id).toBe('json-holder');
    expect(json(join(manualSource, 'vericred.config.json')).dataSource).toEqual({ type: 'manual' });
  }, 30_000);
  it('rejects an online writer and never publishes a backup', async () => {
    const release = await acquireDataLease();
    try { await expect(backupData(source, backup, secret)).rejects.toThrow(/lock/i); }
    finally { await release(); }
    expect(existsSync(backup)).toBe(false);
  });
  it('rejects a wrong backup secret against existing encrypted state', async () => {
    new EncryptedMap('preauth-codes').set('synthetic', { expiresAt: Date.now() });
    await expect(backupData(source, backup, 'incorrect-secret-'.repeat(3))).rejects.toThrow(/authenticate existing encrypted state/);
    expect(existsSync(backup)).toBe(false);
  });
  it('rejects wrong restoration secrets and leaves the target absent', async () => {
    await backupData(source, backup, secret);
    await expect(restoreData(backup, restored, 'incorrect-secret-'.repeat(3))).rejects.toThrow(/authentication failed/);
    expect(existsSync(restored)).toBe(false);
  });
  it('rejects ciphertext corruption and cleans only its own staging directory', async () => {
    await backupData(source, backup, secret);
    const path = join(backup, 'files', '0.gcm'); const blob = readFileSync(path); blob[0] ^= 1; writeFileSync(path, blob);
    await expect(restoreData(backup, restored, secret)).rejects.toThrow(/authentication failed/);
    expect(existsSync(restored)).toBe(false); expect(existsSync(join(source, 'issuer-key.json'))).toBe(true);
  });
  it('authenticates the manifest before using any path', async () => {
    await backupData(source, backup, secret);
    const path = join(backup, 'manifest.json'); const manifest = json(path); manifest.manifest.files[0].path = '../outside.json'; writeFileSync(path, JSON.stringify(manifest));
    await expect(restoreData(backup, restored, secret)).rejects.toThrow(/authentication failed/);
    expect(existsSync(join(fixture, 'outside.json'))).toBe(false); expect(existsSync(restored)).toBe(false);
  });
  it('refuses overwrite and nested destinations', async () => {
    await expect(backupData(source, join(source, 'nested'), secret)).rejects.toThrow(/separate directories/);
    await backupData(source, backup, secret);
    await expect(backupData(source, backup, secret)).rejects.toThrow(/already exists/);
    mkdirSync(restored); writeFileSync(join(restored, 'sentinel.txt'), 'must survive');
    await expect(restoreData(backup, restored, secret)).rejects.toThrow(/already exists/);
    expect(readFileSync(join(restored, 'sentinel.txt'), 'utf8')).toBe('must survive');
    await expect(restoreData(backup, join(backup, 'nested'), secret)).rejects.toThrow(/separate directories/);
  });
  it('refuses a partial backup of a local source outside the persistent volume', async () => {
    const config = json(join(source, 'vericred.config.json')); config.dataSource.path = join(fixture, 'outside.json');
    writeFileSync(join(source, 'vericred.config.json'), JSON.stringify(config));
    await expect(backupData(source, backup, secret)).rejects.toThrow(/outside DATA_DIR/);
    expect(existsSync(backup)).toBe(false);
  });
});