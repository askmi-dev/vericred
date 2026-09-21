import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import https from 'node:https';
import { setTimeout as delay } from 'node:timers/promises';
import { createSyntheticEudiMaterial } from './lib/synthetic-eudi-material.mjs';
import { issueSyntheticEudiCredential, verifyRetiredTokenStatus } from './lib/synthetic-eudi-client.mjs';

// Local synthetic recovery drill, never a deployment or independent wallet/vault acceptance.
const image = process.argv[2] ?? 'vericred:acceptance-20260920-provisioning';
assert(process.argv.length <= 3); assert.match(image, /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$/);
const exec = promisify(execFile), id = randomUUID(), label = 'com.vericred.eudi-restore';
const prefix = 'vericred-eudi-restore-' + id, backend = prefix + '-back', frontend = prefix + '-front';
const sourceVolume = prefix + '-source', backupVolume = prefix + '-backup', restoredVolume = prefix + '-restored';
const volumes = [sourceVolume, backupVolume, restoredVolume], containers = [];
const proxy = prefix + '-proxy', provider = prefix + '-provider', source = prefix + '-source-app', recovered = prefix + '-recovered-app';
const artifactRoot = resolve('.validation-artifacts'); mkdirSync(artifactRoot, { recursive: true });
const fixture = mkdtempSync(join(artifactRoot, 'eudi-restore-'));
const materialDir = join(fixture, 'seed', 'material'), deployedMaterial = join(fixture, 'deployed-material'), recoveredMaterial = join(fixture, 'recovered-material');
const statusUri = 'https://wallet-status:9443/lists/storage';
const caddyImage = 'caddy:2.11.4-alpine';
let environment = { ...process.env }, origin, ca, stage = 'synthetic fixture', summary;
const restrictions = ['--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m'];
async function docker(args, timeout = 60000) {
  return (await exec('docker', args, { env: environment, windowsHide: true, timeout, maxBuffer: 1024 * 1024 })).stdout.trim();
}
async function ownedRemove(kind, name) {
  const list = await docker(kind === 'container' ? ['ps', '-a', '--format', '{{.Names}}'] : [kind, 'ls', '--format', '{{.Name}}']);
  if (!list.split(/\r?\n/).includes(name)) return;
  const item = JSON.parse(await docker([kind, 'inspect', name]))[0];
  assert.equal((kind === 'container' ? item.Config.Labels : item.Labels)?.[label], id, 'Ownership mismatch');
  await docker(kind === 'container' ? ['rm', '-f', '-v', name] : [kind, 'rm', name]);
}
function mount(source, target, readonly = false, type = 'volume') { return ['--mount', `type=${type},src=${source},dst=${target}${readonly ? ',readonly' : ''}`]; }
async function job(name, mounts, command, settings = []) {
  const container = prefix + '-' + name; containers.push(container);
  return docker(['run', '--name', container, '--label', label + '=' + id, '--network', 'none', ...restrictions,
    ...mounts, '-e', 'NODE_ENV=production', '-e', 'ADMIN_API_KEY', '-e', 'PSEUDO_SECRET', ...settings, image, ...command]);
}
function settings(material, data = '/app/data') {
  return [...mount(material, '/run/eudi', true, 'bind'), '-e', 'DATA_DIR=' + data, '-e', 'WALLET_PROFILE=eudi-android', '-e', 'EUDI_REGISTRATION_POLICY=required',
    '-e', 'EUDI_ISSUER_REGISTRAR_DATASET_PATH=/run/eudi/issuer-registrar-dataset.json', '-e', 'EUDI_VERIFIER_REGISTRAR_DATASET_PATH=/run/eudi/verifier-registrar-dataset.json',
    '-e', 'EUDI_ISSUER_CERT_CHAIN_PATH=/run/eudi/issuer-chain.pem', '-e', 'EUDI_VERIFIER_CERT_CHAIN_PATH=/run/eudi/verifier-chain.pem',
    '-e', 'EUDI_VERIFIER_KEY_PATH=/run/eudi/verifier-key.pem', '-e', 'EUDI_ISSUER_REGISTRATION_CERT_PATH=/run/eudi/issuer-registration.jwt',
    '-e', 'EUDI_VERIFIER_REGISTRATION_CERT_PATH=/run/eudi/verifier-registration.jwt', '-e', 'EUDI_WALLET_ATTESTATION_POLICY_PATH=/run/eudi/wallet-attestation-policy.json',
    '-e', 'NODE_EXTRA_CA_CERTS=/run/eudi/provider-tls-cert.pem'];
}
async function request(path, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolveRequest, reject) => {
    const req = https.request(new URL(path, origin), { method, headers, ca, servername: 'localhost', rejectUnauthorized: true,
      lookup: (_host, options, callback) => options?.all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4),
    }, res => {
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > 1024 * 1024) res.destroy(new Error('Response too large')); else chunks.push(chunk); });
      res.on('error', reject); res.on('end', () => resolveRequest({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.setTimeout(15000, () => req.destroy(new Error('Local request timeout'))); req.on('error', reject); if (body) req.write(body); req.end();
  });
}
const post = (body, admin = false) => ({ method: 'POST', headers: { 'Content-Type': 'application/json', ...(admin ? { Authorization: 'Bearer ' + environment.ADMIN_API_KEY } : {}) }, body: JSON.stringify(body) });
async function json(path, options) { const r = await request(path, options); assert.equal(r.status, 200, 'Unexpected endpoint status: ' + path); try { return JSON.parse(r.body); } catch { throw new Error('Invalid endpoint JSON'); } }
async function offer() { return (await json('/offer', post({ holderId: 'synthetic-adult', credentialType: 'AgeCredential' }, true))).offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']; }
const redeem = code => json('/token', post({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }));
async function startApp(name, volume, material, dataPath = '/app/data') {
  containers.push(name);
  const proxyIp = JSON.parse(await docker(['inspect', proxy]))[0].NetworkSettings.Networks[backend].IPAddress;
  await docker(['run', '-d', '--name', name, '--label', label + '=' + id, '--network', backend, '--network-alias', 'gateway', '--init', ...restrictions,
    ...mount(volume, dataPath === '/app/data' ? '/app/data' : '/recovery'), ...settings(material, dataPath),
    '-e', 'NODE_ENV=production', '-e', 'ADMIN_API_KEY', '-e', 'PSEUDO_SECRET', '-e', 'TRUSTED_PROXY_CIDRS=' + proxyIp + '/32', image]);
  for (let attempt = 0; attempt < 50; attempt++) {
    assert(JSON.parse(await docker(['inspect', '--format', '{{json .State}}', name])).Running, 'Gateway exited during startup');
    try { const r = await request('/health'); if (r.status === 200 && JSON.parse(r.body).status === 'ok') return; } catch {}
    await delay(500);
  }
  throw new Error('Gateway did not become healthy');
}
try {
  mkdirSync(join(fixture, 'seed')); const seed = await createSyntheticEudiMaterial(join(fixture, 'seed'), 'https://localhost');
  environment = { ...environment, ADMIN_API_KEY: seed.adminApiKey, PSEUDO_SECRET: seed.pseudonymSecret };
  const openssl = process.env.OPENSSL_BIN ?? (existsSync('C:/Program Files/Git/usr/bin/openssl.exe') ? 'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl');
  await exec(openssl, ['req', '-new', '-x509', '-key', join(materialDir, 'tls-key.pem'), '-out', join(materialDir, 'provider-tls-cert.pem'), '-days', '2', '-subj', '/CN=wallet-status', '-addext', 'subjectAltName=DNS:wallet-status', '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature', '-addext', 'extendedKeyUsage=serverAuth'], { windowsHide: true, timeout: 15000 });
  const policyPath = join(materialDir, 'wallet-attestation-policy.json'); const policy = JSON.parse(readFileSync(policyPath)); policy.providers[0].statusListPrefixes = ['https://wallet-status:9443/lists/']; writeFileSync(policyPath, JSON.stringify(policy));
  // Simulated external secret store only: a separate in-memory recovery key encrypts deployment material.
  // Provider private keys belong to the test wallet/provider and are never mounted into the gateway.
  const names = ['issuer-registrar-dataset.json', 'verifier-registrar-dataset.json', 'issuer-chain.pem', 'verifier-chain.pem', 'verifier-key.pem', 'issuer-registration.jwt', 'verifier-registration.jwt', 'wallet-attestation-policy.json', 'provider-tls-cert.pem'];
  const files = Object.fromEntries(names.map(name => [name, readFileSync(join(materialDir, name)).toString('base64')]));
  mkdirSync(deployedMaterial, { mode: 0o700 }); for (const name of names) writeFileSync(join(deployedMaterial, name), Buffer.from(files[name], 'base64'), { flag: 'wx', mode: 0o600 });
  const vaultKey = randomBytes(32), iv = randomBytes(12), aad = Buffer.from('VeriCred synthetic material recovery fixture v1');
  const cipher = createCipheriv('aes-256-gcm', vaultKey, iv); cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify({ files, adminApiKey: seed.adminApiKey, pseudonymSecret: seed.pseudonymSecret })), cipher.final()]);
  const envelope = { iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), encrypted: encrypted.toString('base64') };
  const vaultPath = join(fixture, 'synthetic-material-store.json'); writeFileSync(vaultPath, JSON.stringify(envelope), { mode: 0o600 });
  function recoverVault(value) { const decipher = createDecipheriv('aes-256-gcm', vaultKey, Buffer.from(value.iv, 'hex')); decipher.setAAD(aad); decipher.setAuthTag(Buffer.from(value.tag, 'hex')); return JSON.parse(Buffer.concat([decipher.update(Buffer.from(value.encrypted, 'base64')), decipher.final()]).toString('utf8')); }
  const altered = { ...envelope, tag: (envelope.tag[0] === '0' ? '1' : '0') + envelope.tag.slice(1) }; assert.throws(() => recoverVault(altered));
  stage = 'local services'; console.log('EUDI restore: isolated TLS proxy, synthetic provider and fresh source volume');
  const appId = await docker(['image', 'inspect', image, '--format', '{{.Id}}']); const caddyId = await docker(['image', 'inspect', caddyImage, '--format', '{{.Id}}']);
  await docker(['network', 'create', '--internal', '--label', label + '=' + id, backend]); await docker(['network', 'create', '--label', label + '=' + id, frontend]);
  for (const volume of volumes) { await docker(['volume', 'create', '--label', label + '=' + id, volume]); await job('init-' + volume.split('-').at(-1), mount(volume, '/app/data'), ['node', '-e', 'require("node:fs").accessSync("/app/data",require("node:fs").constants.W_OK)']); }
  const providerScript = `import https from 'node:https'; import fs from 'node:fs'; import {SignJWT} from 'jose'; import {createPrivateKey,X509Certificate} from 'node:crypto'; import {deflateSync} from 'node:zlib';
    const key=createPrivateKey(fs.readFileSync('/fixture/wallet-status-provider-key.pem')); const cert=new X509Certificate(fs.readFileSync('/fixture/wallet-status-provider-cert.pem'));
    https.createServer({key:fs.readFileSync('/fixture/tls-key.pem'),cert:fs.readFileSync('/fixture/provider-tls-cert.pem')},async(req,res)=>{if(req.url!='/lists/storage'){res.writeHead(404).end();return;}const now=Math.floor(Date.now()/1000);const jwt=await new SignJWT({sub:'${statusUri}',iat:now,exp:now+120,ttl:60,status_list:{bits:1,lst:deflateSync(Buffer.alloc(32)).toString('base64url')}}).setProtectedHeader({alg:'ES256',typ:'statuslist+jwt',x5c:[cert.raw.toString('base64')]}).sign(key);res.setHeader('Content-Type','application/statuslist+jwt');res.end(jwt);}).listen(9443,'0.0.0.0');`;
  containers.push(provider); await docker(['run', '-d', '--name', provider, '--label', label + '=' + id, '--network', backend, '--network-alias', 'wallet-status', ...restrictions, ...mount(materialDir, '/fixture', true, 'bind'), image, 'node', '--input-type=module', '-e', providerScript]);
  const template = readFileSync('deploy/Caddyfile.acceptance', 'utf8'); writeFileSync(join(fixture, 'Caddyfile'), '{\n admin off\n}\n' + template.replace('{$ACCEPTANCE_HOST} {', '{$ACCEPTANCE_HOST} {\n tls /fixture/tls-cert.pem /fixture/tls-key.pem'));
  ca = readFileSync(join(materialDir, 'tls-cert.pem')); containers.push(proxy);
  await docker(['run', '-d', '--name', proxy, '--label', label + '=' + id, '--network', frontend, '-p', '127.0.0.1::443', '-e', 'ACCEPTANCE_HOST=localhost', ...mount(join(fixture, 'Caddyfile'), '/etc/caddy/Caddyfile', true, 'bind'), ...mount(materialDir, '/fixture', true, 'bind'), caddyImage]);
  await docker(['network', 'connect', backend, proxy]); const port = Number((await docker(['port', proxy, '443/tcp'])).split(':').at(-1)); origin = 'https://localhost:' + port;
  const configPath = join(fixture, 'seed', 'data', 'vericred.config.json'), config = JSON.parse(readFileSync(configPath)); config.issuer.url = origin; config.issuer.did = 'did:web:localhost%3A' + port; writeFileSync(configPath, JSON.stringify(config));
  await job('seed', [...mount(sourceVolume, '/app/data'), ...mount(join(fixture, 'seed', 'data'), '/seed', true, 'bind')], ['node', '-e', 'require("node:fs").cpSync("/seed","/app/data",{recursive:true})']);
  await startApp(source, sourceVolume, deployedMaterial);
  const client = () => issueSyntheticEudiCredential({ request, origin, materialDir, adminApiKey: environment.ADMIN_API_KEY, statusUri });
  stage = 'pre-snapshot issuance'; const issued = await client(); const pending = await offer();
  const tokenStartedAt = Date.now();
  const unusedToken = await redeem(await offer());
  assert(typeof unusedToken.access_token === 'string' && unusedToken.access_token.length > 0, 'Missing access token');
  assert(Number.isSafeInteger(unusedToken.expires_in) && unusedToken.expires_in > 0, 'Invalid token lifetime');
  const unusedTokenRequest = { ...post({}), headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + unusedToken.access_token } };
  const beforeToken = await request('/credentials', unusedTokenRequest);
  assert.equal(beforeToken.status, 400); assert.equal(JSON.parse(beforeToken.body).error, 'invalid_encryption_parameters');
  const vp = await json('/api/oid4vp/initiate', post({ credentialType: 'AgeCredential' }, true));
  const login = await request('/admin/login', post({ apiKey: environment.ADMIN_API_KEY })); assert.equal(login.status, 302); const cookie = login.headers['set-cookie'][0].split(';')[0];
  assert.equal((await request('/admin/api/config', { headers: { Cookie: cookie } })).status, 200);
  assert.equal((await json('/api/oid4vp/session/' + vp.sessionId, { headers: { Authorization: 'Bearer ' + vp.readToken } })).status, 'initiated');
  const before = await json('/.well-known/jwks.json');
  stage = 'application snapshot'; console.log('EUDI restore: encrypted application backup, then post-snapshot revocation and issuance');
  await docker(['stop', '-t', '15', source]);
  await job('backup', [...mount(sourceVolume, '/app/data'), ...mount(backupVolume, '/backup')], ['node', 'scripts/backup-restore.mjs', 'backup', '/app/data', '/backup/snapshot', '--offline']);
  await docker(['start', source]);
  let restarted = false;
  for (let i = 0; i < 40; i++) { try { if ((await request('/health')).status === 200) { restarted = true; break; } } catch {} await delay(500); }
  assert(restarted, 'Source gateway did not become healthy after backup');
  assert.equal((await json('/admin/revoke', post({ credentialId: issued.credentialId, reason: 'Synthetic post-snapshot revocation' }, true))).success, true);
  await redeem(pending);
  const unseen = await client(); assert.equal(unseen.listId, issued.listId); assert(unseen.statusIndex > issued.statusIndex);
  await docker(['stop', '-t', '15', source]); await ownedRemove('container', source);
  stage = 'separate material recovery'; const restoredSecretStore = recoverVault(JSON.parse(readFileSync(vaultPath)));
  mkdirSync(recoveredMaterial, { mode: 0o700 });
  for (const name of names) { const content = Buffer.from(restoredSecretStore.files[name], 'base64'); assert(content.equals(Buffer.from(files[name], 'base64')), 'Recovered material mismatch'); writeFileSync(join(recoveredMaterial, name), content, { flag: 'wx', mode: 0o600 }); }
  environment = { ...environment, ADMIN_API_KEY: restoredSecretStore.adminApiKey, PSEUDO_SECRET: restoredSecretStore.pseudonymSecret };
  stage = 'separate-volume restore'; console.log('EUDI restore: restore to separate volume and recovered material paths');
  await job('restore', [...mount(backupVolume, '/backup', true), ...mount(restoredVolume, '/recovery')], ['node', 'scripts/backup-restore.mjs', 'restore', '/backup/snapshot', '/recovery/data', '--offline']);
  const preflight = JSON.parse(await job('preflight', mount(restoredVolume, '/recovery', true), ['node', 'scripts/eudi-material-preflight.mjs', '--offline'], settings(recoveredMaterial, '/recovery/data')));
  assert.equal(preflight.status, 'PASS'); assert.equal(preflight.releaseAccepted, false);
  await startApp(recovered, restoredVolume, recoveredMaterial, '/recovery/data');
  stage = 'recovered behavior'; assert.deepEqual(await json('/.well-known/jwks.json'), before);
  assert.equal((await request('/admin/api/config', { headers: { Cookie: cookie } })).status, 401);
  assert.equal((await request('/api/oid4vp/session/' + vp.sessionId, { headers: { Authorization: 'Bearer ' + vp.readToken } })).status, 401);
  assert.equal((await request('/token', post({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': pending }))).status, 400);
  assert(Date.now() < tokenStartedAt + unusedToken.expires_in * 1000, 'Restore check exceeded token lifetime');
  assert.equal((await request('/credentials', unusedTokenRequest)).status, 401);
  await verifyRetiredTokenStatus({ request, origin, materialDir, listId: issued.listId });
  const replacement = await client(); assert.notEqual(replacement.listId, issued.listId); assert.equal(replacement.statusIndex, 0);
  const readiness = await json('/admin/api/readiness', { headers: { Authorization: 'Bearer ' + environment.ADMIN_API_KEY } }); assert.equal(readiness.configurationReady, true); assert.equal(readiness.releaseAccepted, false);
  summary = { status: 'PASS', checkedAt: new Date().toISOString(), image, appId, caddyImage, caddyId,
    scope: 'Isolated Docker-volume EUDI restore with local TLS, synthetic provider and simulated external secret-store recovery',
    checks: ['encrypted issuance before snapshot', 'post-snapshot revocation and unseen issuance', 'separate application backup/recovery volumes', 'separate restored deployment material and secrets', 'tampered simulated store rejection', 'read-only recovered material preflight', 'key continuity', 'active sessions/token baseline and restored rejection before token expiry', 'all old status bits revoked', 'encrypted replacement issuance on a fresh list'],
    independentWalletAcceptance: 'NOT RUN', registrationPolicyOnAcceptance: 'NOT RUN', publicHttpsAcceptance: 'NOT RUN', liveCustomerDatabaseRecovery: 'NOT RUN', productionSecretStoreRecovery: 'NOT RUN',
    sourceSha256: Object.fromEntries(['scripts/eudi-restore-acceptance.mjs', 'scripts/lib/synthetic-eudi-client.mjs', 'scripts/lib/synthetic-eudi-material.mjs', 'deploy/Caddyfile.acceptance'].map(path => [path, createHash('sha256').update(readFileSync(path)).digest('hex')])) };
} catch (error) { console.error('EUDI restore failed at ' + stage + ': ' + error.message); process.exitCode = 1; }
finally {
  const failed = [];
  for (const name of containers.reverse()) try { await ownedRemove('container', name); } catch { failed.push(name); }
  for (const name of volumes) try { await ownedRemove('volume', name); } catch { failed.push(name); }
  for (const name of [backend, frontend]) try { await ownedRemove('network', name); } catch { failed.push(name); }
  if (failed.length) { console.error('Owned resource cleanup failed: ' + failed.join(', ')); process.exitCode = 1; }
}
if (summary && !process.exitCode) { summary.cleanup = 'PASS'; writeFileSync(join(fixture, 'result.json'), JSON.stringify(summary, null, 2)); writeFileSync(join(artifactRoot, 'eudi-restore-acceptance-result.json'), JSON.stringify(summary, null, 2)); console.log('EUDI restore PASS: recovered materials, invalidated old state, fresh encrypted issuance and owned-resource cleanup.'); }
