import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import assert from 'node:assert/strict';

// Only randomly named, labelled resources and synthetic data. This is not wallet/HTTPS acceptance.
const exec = promisify(execFile);
const image = process.argv[2] ?? 'vericred:local';
assert.match(image, /^[a-zA-Z0-9][a-zA-Z0-9._/:@-]*$/, 'Pass a Docker image reference');
const runId = randomUUID();
const prefix = 'vericred-smoke-' + runId;
const volume = prefix + '-data';
const backupVolume = prefix + '-backup';
const recoveryVolume = prefix + '-recovery';
const volumes = [volume, backupVolume, recoveryVolume];
const main = prefix + '-main';
const contender = prefix + '-contender';
const recreated = prefix + '-recreated';
const recovered = prefix + '-recovered';
const label = 'com.vericred.smoke';
const containers = [main, contender, recreated, recovered];
const adminKey = randomBytes(32).toString('hex');
const environment = { ...process.env, ADMIN_API_KEY: adminKey, PSEUDO_SECRET: randomBytes(32).toString('hex') };
const restrictions = ['--read-only', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m'];
let baseUrl;
async function dockerResult(args, timeout = 60_000, extraEnvironment = {}) {
  return exec('docker', args, { timeout, maxBuffer: 4 * 1024 * 1024, env: { ...environment, ...extraEnvironment }, windowsHide: true });
}
async function docker(args, timeout, extraEnvironment) { return (await dockerResult(args, timeout, extraEnvironment)).stdout.trim(); }
async function start(name, storage = volume, mountPath = '/app/data', dataDir = '/app/data') {
  await docker(['run', '-d', '--name', name, '--label', label + '=' + runId, '--init', ...restrictions,
    '--mount', 'type=volume,src=' + storage + ',dst=' + mountPath,
    ...(mountPath === '/app/data' ? [] : ['--tmpfs', '/app/data:rw,noexec,nosuid,size=1m']),
    '-p', '127.0.0.1::3100', '-e', 'NODE_ENV=production', '-e', 'DATA_DIR=' + dataDir,
    '-e', 'ISSUER_URL=https://wallet-smoke.invalid', '-e', 'ADMIN_API_KEY', '-e', 'PSEUDO_SECRET', image]);
}
async function oneOff(suffix, mounts, command) {
  const name = prefix + '-' + suffix; containers.push(name);
  return docker(['run', '--rm', '--name', name, '--label', label + '=' + runId, ...restrictions,
    ...mounts.flatMap(mount => ['--mount', mount]),
    ...(mounts.some(mount => mount.includes('dst=/app/data')) ? [] : ['--tmpfs', '/app/data:rw,noexec,nosuid,size=1m']),
    '-e', 'NODE_ENV=production', '-e', 'PSEUDO_SECRET', image, ...command]);
}
async function initializeVolume(storage, suffix, seed = false) {
  await docker(['volume', 'create', '--label', label + '=' + runId, storage]);
  // Docker copies /app/data ownership (UID 1000) into each new volume. No server runs here.
  await oneOff('initialize-' + suffix, ['type=volume,src=' + storage + ',dst=/app/data'], ['node', '-e', seed
    ? 'require("node:fs").writeFileSync("/app/data/holders.json",JSON.stringify([{id:"docker-smoke-holder",dateOfBirth:"1990-01-01"}]))'
    : 'require("node:fs").accessSync("/app/data",require("node:fs").constants.W_OK)']);
}
async function waitHealthy(name) {
  const port = await docker(['port', name, '3100/tcp']);
  baseUrl = 'http://' + port.split(/\r?\n/)[0];
  for (let attempt = 0; attempt < 60; attempt++) {
    const state = JSON.parse(await docker(['inspect', '--format', '{{json .State}}', name]));
    if (!state.Running) throw new Error('Smoke container exited before becoming healthy');
    if (state.Health?.Status === 'healthy') {
      const response = await fetch(baseUrl + '/health', { signal: AbortSignal.timeout(3_000) });
      if (response.ok && (await response.json()).status === 'ok') return;
    }
    await delay(1_000);
  }
  throw new Error('Smoke container did not become healthy within 60 seconds');
}
async function json(path, options = {}) {
  const response = await fetch(baseUrl + path, { ...options, signal: AbortSignal.timeout(10_000) });
  assert.equal(response.status, 200, path + ' should return HTTP 200');
  return response.json();
}
const post = (body, admin = false) => ({ method: 'POST', headers: {
  'Content-Type': 'application/json', ...(admin ? { Authorization: 'Bearer ' + adminKey } : {}),
}, body: JSON.stringify(body) });
async function offerCode() {
  const offer = await json('/offer', post({ holderId: 'docker-smoke-holder', credentialType: 'AgeCredential' }, true));
  return offer.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
}
const redeem = code => json('/token', post({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }));
async function issueCredential(name, accessToken) {
  const nonce = await json('/nonce', post({}));
  // An independent in-container wallet client signs a real proof and uses HTTP only; no storage modules are imported.
  const script = `
    import assert from 'node:assert/strict';
    import { generateKeyPair, exportJWK, SignJWT, jwtVerify, createLocalJWKSet } from 'jose';
    const pair = await generateKeyPair('ES256');
    const proof = await new SignJWT({ nonce: process.env.SMOKE_NONCE }).setIssuedAt().setAudience('https://wallet-smoke.invalid')
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(pair.publicKey) }).sign(pair.privateKey);
    const response = await fetch('http://127.0.0.1:3100/credentials', { method: 'POST', headers: {
      'Content-Type': 'application/json', Authorization: 'Bearer ' + process.env.SMOKE_ACCESS_TOKEN,
    }, body: JSON.stringify({ credential_configuration_id: 'AgeCredential', proofs: { jwt: [proof] } }), signal: AbortSignal.timeout(10000) });
    assert.equal(response.status, 200, 'Real proof-bound issuance must succeed');
    const body = await response.json(); const credential = body.credentials[0].credential;
    const keys = await (await fetch('http://127.0.0.1:3100/.well-known/jwks.json')).json();
    const { payload } = await jwtVerify(credential.split('~')[0], createLocalJWKSet(keys), { algorithms: ['ES256'] });
    assert.ok(payload.cnf.jwk); assert.ok(payload.jti);
    const status = payload.credentialStatus; assert.equal(status.type, 'StatusList2021Entry');
    console.log(JSON.stringify({ credentialId: payload.jti, listId: new URL(status.statusListCredential).pathname.split('/').pop(), statusIndex: Number(status.statusListIndex) }));
  `;
  return JSON.parse(await docker(['exec', '-e', 'SMOKE_ACCESS_TOKEN', '-e', 'SMOKE_NONCE', name, 'node', '--input-type=module', '-e', script], undefined,
    { SMOKE_ACCESS_TOKEN: accessToken, SMOKE_NONCE: nonce.c_nonce }));
}
async function verifyRetiredList(name, listId) {
  const script = `
    import assert from 'node:assert/strict';
    import { gunzipSync } from 'node:zlib';
    import { jwtVerify, createLocalJWKSet } from 'jose';
    const keys = await (await fetch('http://127.0.0.1:3100/.well-known/jwks.json')).json();
    const response = await fetch('http://127.0.0.1:3100/status/' + encodeURIComponent(process.env.SMOKE_LIST_ID));
    assert.equal(response.status, 200);
    const { payload } = await jwtVerify(await response.text(), createLocalJWKSet(keys), { algorithms: ['ES256'] });
    const bytes = gunzipSync(Buffer.from(payload.credentialSubject.encodedList, 'base64url'));
    assert.ok(bytes.length >= 16384); assert.ok(bytes.every(byte => byte === 255), 'Every pre-recovery status index must be revoked');
    console.log('Signed restored status list: all indices revoked');
  `;
  await docker(['exec', '-e', 'SMOKE_LIST_ID', name, 'node', '--input-type=module', '-e', script], undefined, { SMOKE_LIST_ID: listId });
}
async function cleanup() {
  const errors = [];
  async function removeOwned(kind, name) {
    // --rm helpers can disappear between inspect and rm or still be auto-removing.
    // Query current existence and retry only this exact named, labelled resource.
    const exists = async () => {
      const names = await docker(kind === 'container'
        ? ['ps', '-a', '--format', '{{.Names}}'] : ['volume', 'ls', '--format', '{{.Name}}']);
      return names.split(/\r?\n/).includes(name);
    };
    for (let attempt = 0; attempt < 10; attempt++) {
      if (!await exists()) return;
      try {
        const owner = await docker(kind === 'container'
          ? ['container', 'inspect', '--format', '{{ index .Config.Labels "com.vericred.smoke" }}', name]
          : ['volume', 'inspect', '--format', '{{ index .Labels "com.vericred.smoke" }}', name]);
        if (owner !== runId) throw new Error('Ownership label mismatch; refusing removal');
        await docker(kind === 'container' ? ['rm', '-f', name] : ['volume', 'rm', name]);
        return;
      } catch (error) {
        if (!await exists()) return;
        if (attempt === 9) throw error;
        await delay(300);
      }
    }
  }
  for (const name of containers) {
    try { await removeOwned('container', name); }
    catch { errors.push(name); }
  }
  for (const name of volumes) {
    try { await removeOwned('volume', name); }
    catch { errors.push(name); }
  }
  if (errors.length) throw new Error('Could not clean up smoke resources: ' + errors.join(', '));
}
try {
  console.log('Docker smoke: isolated volume, non-root startup and HTTP boundaries');
  const configuredUser = await docker(['image', 'inspect', '--format', '{{.Config.User}}', image]);
  assert.ok(configuredUser && configuredUser !== '0' && configuredUser !== 'root', 'Image must specify a non-root user');
  await initializeVolume(volume, 'source', true);
  await start(main); await waitHealthy(main);
  assert.notEqual(await docker(['exec', main, 'node', '-e', 'console.log(process.getuid())']), '0');
  assert.equal((await fetch(baseUrl + '/')).status, 200);
  assert.equal((await fetch(baseUrl + '/admin/api/config')).status, 401);
  assert.equal((await fetch(baseUrl + '/dev/navigator')).status, 404);
  const oldDid = await json('/.well-known/did.json'); assert.ok(oldDid.verificationMethod.length > 0);
  const session = await json('/api/oid4vp/initiate', post({ credentialType: 'AgeCredential' }));
  assert.equal((await fetch(baseUrl + '/api/oid4vp/session/' + session.sessionId)).status, 401);
  const code = await offerCode();
  await json('/admin/api/rotate-keys', post({}, true));
  const rotatedDid = await json('/.well-known/did.json');
  assert.equal(rotatedDid.verificationMethod.length, oldDid.verificationMethod.length + 1);
  console.log('Docker smoke: a second writer must fail before serving requests');
  await start(contender);
  assert.notEqual(await docker(['wait', contender], 20_000), '0', 'Second writer must refuse shared DATA_DIR');
  const logs = await dockerResult(['logs', contender]); assert.match(logs.stdout + logs.stderr, /ELOCKED|Lock file is already being held/);
  assert.equal((await json('/health')).status, 'ok');
  console.log('Docker smoke: graceful restart retains key history, sessions and pre-authorized codes');
  await docker(['stop', '-t', '15', main]); await docker(['start', main]); await waitHealthy(main);
  assert.deepEqual((await json('/.well-known/did.json')).verificationMethod, rotatedDid.verificationMethod);
  assert.equal((await json('/api/oid4vp/session/' + session.sessionId, { headers: { Authorization: 'Bearer ' + session.readToken } })).status, 'initiated');
  const token = await redeem(code); assert.ok(token.access_token);
  console.log('Docker smoke: abrupt stop and stale-lease recovery in a replacement container');
  await docker(['kill', '--signal', 'KILL', main]); await delay(32_000);
  await start(recreated); await waitHealthy(recreated);
  assert.deepEqual((await json('/.well-known/did.json')).verificationMethod, rotatedDid.verificationMethod);
  assert.equal((await json('/api/oid4vp/session/' + session.sessionId, { headers: { Authorization: 'Bearer ' + session.readToken } })).status, 'initiated');
  const withToken = await fetch(baseUrl + '/credentials', { ...post({ credential_configuration_id: 'AgeCredential' }),
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token.access_token } });
  assert.equal(withToken.status, 400, 'Persisted access token must be recognized; absent proof must be rejected');

  console.log('Docker smoke: encrypted offline backup and restore into a separate volume');
  const issuedToken = await redeem(await offerCode());
  const issued = await issueCredential(recreated, issuedToken.access_token);
  const pendingCode = await offerCode();
  const login = await fetch(baseUrl + '/admin/login', { ...post({ apiKey: adminKey }), redirect: 'manual' });
  assert.equal(login.status, 302); const cookie = login.headers.get('set-cookie')?.split(';')[0]; assert.ok(cookie);
  await json('/admin/api/csrf-handshake', { headers: { Cookie: cookie } });
  await initializeVolume(backupVolume, 'backup'); await initializeVolume(recoveryVolume, 'recovery');
  await docker(['stop', '-t', '15', recreated]);
  await oneOff('backup', ['type=volume,src=' + volume + ',dst=/app/data', 'type=volume,src=' + backupVolume + ',dst=/backup'],
    ['node', 'scripts/backup-restore.mjs', 'backup', '/app/data', '/backup/snapshot', '--offline']);
  // Change source state AFTER the snapshot through the real routes, then restore the older snapshot.
  await docker(['start', recreated]); await waitHealthy(recreated);
  assert.equal((await json('/admin/revoke', post({ credentialId: issued.credentialId, reason: 'Synthetic post-backup revocation' }, true))).success, true);
  await redeem(pendingCode);
  const afterSnapshotToken = await redeem(await offerCode());
  const afterSnapshot = await issueCredential(recreated, afterSnapshotToken.access_token);
  assert.equal(afterSnapshot.listId, issued.listId); assert.ok(afterSnapshot.statusIndex > issued.statusIndex);
  await docker(['stop', '-t', '15', recreated]);
  await oneOff('restore', ['type=volume,src=' + backupVolume + ',dst=/backup,readonly', 'type=volume,src=' + recoveryVolume + ',dst=/recovery'],
    ['node', 'scripts/backup-restore.mjs', 'restore', '/backup/snapshot', '/recovery/data', '--offline']);
  await start(recovered, recoveryVolume, '/recovery', '/recovery/data'); await waitHealthy(recovered);
  assert.deepEqual((await json('/.well-known/did.json')).verificationMethod, rotatedDid.verificationMethod);
  assert.equal((await fetch(baseUrl + '/admin/api/config', { headers: { Cookie: cookie } })).status, 401, 'Restored admin sessions must be invalidated');
  assert.equal((await fetch(baseUrl + '/api/oid4vp/session/' + session.sessionId, { headers: { Authorization: 'Bearer ' + session.readToken } })).status, 401);
  const replay = await fetch(baseUrl + '/token', post({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': pendingCode }));
  assert.equal(replay.status, 400); assert.equal((await replay.json()).error, 'invalid_grant');
  const oldAccess = await fetch(baseUrl + '/credentials', { ...post({ credential_configuration_id: 'AgeCredential' }),
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + issuedToken.access_token } });
  assert.equal(oldAccess.status, 401, 'Restored access tokens must be invalidated');
  await verifyRetiredList(recovered, issued.listId);
  const freshToken = await redeem(await offerCode()); const fresh = await issueCredential(recovered, freshToken.access_token);
  assert.notEqual(fresh.listId, issued.listId); assert.equal(fresh.statusIndex, 0);
  await docker(['stop', '-t', '15', recovered]);
  console.log('Docker smoke PASS: health, auth, non-root, restart, crash recovery, separate-volume restore, revocation rollback protection and single-writer lease');
} catch (error) {
  console.error('Docker smoke FAIL:', error.message); process.exitCode = 1;
} finally {
  try { await cleanup(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}