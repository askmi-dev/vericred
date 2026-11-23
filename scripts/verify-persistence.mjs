// Runs only against disposable local processes/containers and synthetic data.
// npm run build first; optional: node scripts/verify-persistence.mjs --image IMAGE
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, chmodSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { createServer } from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { createHmac, randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT, importJWK, jwtVerify, calculateJwkThumbprint } from 'jose';

const imageIndex = process.argv.indexOf('--image');
const image = imageIndex === -1 ? undefined : process.argv[imageIndex + 1];
if (imageIndex !== -1 && !image) throw new Error('--image requires an image tag');
const dir = mkdtempSync(`${tmpdir()}/vericred-lifecycle-`);
const active = new Set();
const adminKey = 'synthetic-lifecycle-admin-key';
const hashKey = 'synthetic-lifecycle-provenance-key';
const holderId = 'lifecycle-holder';
let url;

async function freePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise((done) => server.close(done));
  return port;
}

function launch(port, overrides = {}) {
  const env = {
    NODE_ENV: 'production', DEMO_MODE: 'false', OFFER_STORE: 'file',
    DATA_DIR: image ? '/data' : dir, PORT: String(image ? 3100 : port),
    ISSUER_URL: url, ADMIN_API_KEY: adminKey,
    PSEUDO_SECRET: 'synthetic-lifecycle-pseudonym-key', PROVENANCE_HASH_KEY: hashKey,
    ...overrides,
  };
  const name = `vericred-gate-${randomUUID()}`;
  const args = image
    ? ['run', '--rm', '--name', name, '-p', `127.0.0.1:${port}:3100`, '--mount', `type=bind,source=${dir},target=/data`,
      ...Object.entries(env).flatMap(([key, value]) => ['-e', `${key}=${value}`]), image]
    : [resolve('dist/server.js')];
  const child = spawn(image ? 'docker' : process.execPath, args, {
    env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const item = { child, name, port, logs: '', done: false };
  item.result = new Promise((done, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => { item.done = true; done({ code, signal }); });
  });
  child.stdout.on('data', (data) => { item.logs += data; });
  child.stderr.on('data', (data) => { item.logs += data; });
  active.add(item);
  return item;
}

async function stop(item) {
  if (!item.done) {
    if (image) spawnSync('docker', ['kill', item.name], { stdio: 'ignore', timeout: 10000 });
    else item.child.kill('SIGKILL');
    await Promise.race([item.result, delay(10000).then(() => { throw new Error('Stop timed out'); })]);
  }
  active.delete(item);
}

async function ready(item) {
  for (let i = 0; i < 150; i++) {
    if (item.done) throw new Error(`Server exited before readiness: ${item.logs}`);
    try {
      const res = await fetch(`http://127.0.0.1:${item.port}/.well-known/openid-credential-issuer`, { signal: AbortSignal.timeout(500) });
      if (res.ok) return;
    } catch { /* readiness has a bounded retry window */ }
    await delay(100);
  }
  throw new Error(`Readiness timed out: ${item.logs}`);
}

async function post(path, body, token) {
  const res = await fetch(`${url}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
  return { status: res.status, body: await res.json() };
}

function state() { return JSON.parse(readFileSync(`${dir}/offer-state.json`, 'utf8')); }
function provenance() {
  return readFileSync(`${dir}/provenance/issuance.jsonl`, 'utf8').trim().split('\n').map((line) => JSON.parse(line));
}
function permissions(item, mode) {
  if (image) {
    const result = spawnSync('docker', ['exec', '-u', '0', item.name, 'chmod', mode, '/data'], { encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, result.stderr);
  } else chmodSync(dir, Number.parseInt(mode, 8));
}

try {
  const port = await freePort();
  url = `http://127.0.0.1:${port}`;
  const holders = [{ id: holderId, email: 'synthetic@example.invalid', organization: 'Approved Org', membershipType: 'premium' }];
  writeFileSync(`${dir}/holders.json`, JSON.stringify(holders));
  writeFileSync(`${dir}/vericred.config.json`, JSON.stringify({
    issuer: { name: 'Lifecycle Test', url, did: `did:web:localhost%3A${port}` },
    credential: { type: 'MembershipCredential', expiresInDays: 30 },
    dataSource: { type: 'json', path: image ? '/data/holders.json' : `${dir}/holders.json` },
    fieldMappings: { organization: 'organization', membershipType: 'membershipType' },
  }));

  let server = launch(port);
  await ready(server);
  const offered = await post('/offer', { holderId }, adminKey);
  assert.equal(offered.status, 200);
  assert.equal(offered.body.consent_required, true);
  const consentId = offered.body.consent_url.split('/consent/')[1];
  const approved = await post(`/consent/${consentId}/decide`, { approved: true });
  assert.equal(approved.status, 200);
  const code = approved.body.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
  const pending = state().preAuthCodes.find(([key]) => key === code)[1];
  const expectedClaims = { organization: 'Approved Org', membership_type: 'premium' };
  assert.deepEqual(pending.claims, expectedClaims);
  assert.equal(pending.provenance.identifierHash, createHmac('sha256', hashKey).update(holderId).digest('hex'));
  const expectedProvenance = pending.provenance;

  await stop(server); // Real process/container death, no releaseLock hook.
  // Change the live source; recovered issuance must use the approved snapshot.
  if (image) {
    // Volume ownership is now the container node user's. A one-shot helper
    // writes synthetic test data without changing the production entrypoint.
    const changed = spawnSync('docker', ['run', '--rm', '--mount', `type=bind,source=${dir},target=/data`,
      '--entrypoint', 'node', image, '-e', `require('fs').writeFileSync('/data/holders.json', ${JSON.stringify(JSON.stringify([{ ...holders[0], organization: 'Changed Org' }]))})`], { encoding: 'utf8', timeout: 10000 });
    assert.equal(changed.status, 0, changed.stderr);
  } else writeFileSync(`${dir}/holders.json`, JSON.stringify([{ ...holders[0], organization: 'Changed Org' }]));
  server = launch(port);
  await ready(server);
  const tokenRequest = { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code };
  const minted = await post('/token', tokenRequest);
  assert.equal(minted.status, 200);
  const token = minted.body.access_token;
  assert.deepEqual(state().accessTokens.find(([key]) => key === token)[1].provenance, expectedProvenance);

  await stop(server);
  server = launch(port);
  await ready(server);
  const replay = await post('/token', tokenRequest);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');

  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  async function proof(nonce) {
    return new SignJWT({ nonce }).setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk })
      .setAudience(url).setIssuedAt().sign(privateKey);
  }
  const credentialRequest = (jwt) => ({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt } });
  const firstProof = await proof(minted.body.c_nonce);
  const before = state().accessTokens.find(([key]) => key === token)[1];
  permissions(server, '500');
  const refused = await post('/credentials', credentialRequest(firstProof), token);
  assert.equal(refused.status, 500);
  assert.equal(refused.body.error, 'server_error');
  assert.equal(refused.body.credential, undefined);
  permissions(server, '700');
  assert.deepEqual(state().accessTokens.find(([key]) => key === token)[1], before);
  assert(!server.logs.includes('[issuer] Issued'), 'Failed nonce commit must not reach issuance');

  const issued = await post('/credentials', credentialRequest(firstProof), token);
  assert.equal(issued.status, 200);
  const parts = issued.body.credential.split('~');
  const did = await (await fetch(`${url}/.well-known/did.json`)).json();
  const issuerKey = await importJWK(did.verificationMethod[0].publicKeyJwk, 'ES256');
  const verified = await jwtVerify(parts[0], issuerKey);
  assert.equal(verified.payload.cnf.jkt, await calculateJwkThumbprint(jwk));
  const disclosed = Object.fromEntries(parts.slice(1).filter(Boolean).map((part) => {
    const [, key, value] = JSON.parse(Buffer.from(part, 'base64url').toString());
    return [key, value];
  }));
  assert.deepEqual(disclosed, expectedClaims);
  const record = provenance().find((entry) => entry.credentialId === verified.payload.jti);
  assert(record);
  assert.equal(record.lookup.identifierHash, expectedProvenance.identifierHash);
  assert.equal(record.lookup.at, expectedProvenance.lookupAt);
  assert.equal(record.source.connectorType, expectedProvenance.connectorType);
  assert.deepEqual(record.consentGate, { used: true, claimsSnapshot: true });
  assert.equal(statSync(`${dir}/offer-state.json`).mode & 0o077, 0);

  await stop(server);
  server = launch(port);
  await ready(server);
  const proofReplay = await post('/credentials', credentialRequest(firstProof), token);
  assert.equal(proofReplay.status, 400);
  assert.equal(proofReplay.body.credential, undefined);
  assert(provenance().some((entry) => entry.credentialId === verified.payload.jti));
  // Two requests verifying one nonce must not both issue.
  const concurrentProof = await proof(issued.body.c_nonce);
  const simultaneous = await Promise.all([1, 2].map(() => post('/credentials', credentialRequest(concurrentProof), token)));
  assert.equal(simultaneous.filter((entry) => entry.status === 200).length, 1);
  await stop(server);
  console.log('PASS: killed/restarted server preserves consent, pending offer, token, nonce and provenance; replay and nonce-write failure fail closed');

  // Both contenders use normal locking and start before either is ready.
  for (let round = 0; round < 3; round++) {
    const contenders = [launch(await freePort()), launch(await freePort())];
    for (let i = 0; i < 150 && !contenders.some((item) => item.done); i++) await delay(100);
    const losers = contenders.filter((item) => item.done);
    assert.equal(losers.length, 1, 'Exactly one competing writer must be refused');
    assert.match(losers[0].logs, /exclusive offer-store writer lock/);
    const winner = contenders.find((item) => !item.done);
    await ready(winner);
    await stop(winner);
    await stop(losers[0]);
  }
  console.log('PASS: simultaneous writers excluded in three rounds, lock recovered after forced termination');

  for (let attempt = 0; attempt < 3; attempt++) {
    const badPort = await freePort();
    const bad = launch(badPort, { DEMO_MODE: 'true' });
    const result = await Promise.race([bad.result, delay(15000).then(() => { throw new Error('Misconfigured startup did not stop'); })]);
    assert.equal(result.code, 1);
    assert.match(bad.logs, /DEMO_MODE=true is incompatible with NODE_ENV=production/);
    await assert.rejects(fetch(`http://127.0.0.1:${badPort}/.well-known/openid-credential-issuer`, { signal: AbortSignal.timeout(500) }));
    await stop(bad);
  }
  console.log('PASS: repeated production/demo startup fails with exit 1, no healthy listener and remediation diagnostics');
} finally {
  for (const item of active) await stop(item);
  if (image) {
    spawnSync('docker', ['run', '--rm', '--user', '0', '--mount', `type=bind,source=${dir},target=/data`,
      '--entrypoint', 'sh', image, '-c', 'chmod -R 777 /data'], { stdio: 'ignore', timeout: 10000 });
  } else chmodSync(dir, 0o700);
  rmSync(dir, { recursive: true, force: true });
}
