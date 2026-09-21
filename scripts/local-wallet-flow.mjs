import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, createLocalJWKSet } from 'jose';

// An explicit synthetic protocol client, not an independent EUDI or miTch wallet.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = join(root, '.validation-artifacts', 'local-walkthrough');
const origin = 'http://127.0.0.1:3310';
const report = { kind: 'synthetic-local-http-custom-profile', independentWalletAcceptance: 'NOT RUN', startedAt: new Date().toISOString(), steps: [], outcome: 'FAIL' };
const reportPath = join(fixture, 'flow-result.json');
const marker = JSON.parse(readFileSync(join(fixture, 'fixture.json'), 'utf8').replace(/^\uFEFF/, ''));
assert.equal(marker.purpose, 'vericred-local-walkthrough'); assert.equal(marker.origin, origin);
const { adminApiKey } = JSON.parse(readFileSync(join(fixture, 'secrets.json'), 'utf8'));
assert.equal(typeof adminApiKey, 'string'); assert.ok(adminApiKey.length >= 32);
async function request(path, body, authorization) {
  assert.ok(path.startsWith('/') && !path.startsWith('//'));
  return fetch(origin + path, { method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(15000),
    headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(authorization ? { Authorization: 'Bearer ' + authorization } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
}
async function json(path, body, authorization) { const response = await request(path, body, authorization); assert.equal(response.status, 200, path + ' HTTP status'); return response.json(); }
function passed(step, details = {}) { report.steps.push({ step, result: 'PASS', ...details }); console.log('PASS: ' + step); }
try {
  const readiness = await json('/admin/api/readiness', undefined, adminApiKey);
  assert.equal(readiness.walletProfile, 'custom'); assert.equal(readiness.issuer.url, origin); assert.equal(readiness.source.type, 'json');
  assert.equal(readiness.issuer.name, 'VeriCred Local Walkthrough');
  const holderRows = await json('/admin/api/holders', undefined, adminApiKey);
  assert.ok(holderRows.some(row => row._lookupIdentifier === 'walkthrough-adult'));
  passed('Source lookup', { source: 'isolated synthetic JSON holders', holderId: 'walkthrough-adult' });
  const keys = createLocalJWKSet(await json('/.well-known/jwks.json'));
  async function issue(holderId) {
    const offer = await json('/offer', { holderId, credentialType: 'AgeCredential' }, adminApiKey);
    const code = offer.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
    const token = await json('/token', { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code });
    const nonce = await json('/nonce', {});
    const pair = await generateKeyPair('ES256'); const jwk = await exportJWK(pair.publicKey);
    const proof = await new SignJWT({ nonce: nonce.c_nonce }).setAudience(origin).setIssuedAt()
      .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk }).sign(pair.privateKey);
    const body = { credential_configuration_id: 'AgeCredential', proofs: { jwt: [proof] } };
    const issued = await json('/credentials', body, token.access_token);
    const [issuerJwt, ...disclosures] = issued.credentials[0].credential.split('~').filter(Boolean);
    const verified = await jwtVerify(issuerJwt, keys, { algorithms: ['ES256'], typ: 'dc+sd-jwt', issuer: readiness.issuer.did });
    assert.deepEqual(verified.payload.cnf.jwk, jwk);
    assert.equal(verified.payload.vct, 'urn:vericred:credential:AgeCredential:1');
    const names = disclosures.map(d => JSON.parse(Buffer.from(d, 'base64url').toString('utf8'))[1]);
    assert.ok(names.includes('age_over_18')); assert.ok(!names.includes('dateOfBirth'));
    const proofReplay = await request('/credentials', body, token.access_token); assert.equal(proofReplay.status, 400);
    const grantReplay = await request('/token', { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }); assert.equal(grantReplay.status, 400);
    return { pair, issuerJwt, disclosures, payload: verified.payload };
  }
  const issued = await issue('walkthrough-adult');
  passed('Offer, one-use grant, holder proof and signed issuance', { credentialId: issued.payload.jti, credentialType: 'AgeCredential', dateOfBirthDisclosed: false });
  passed('Consumed grant and proof replay rejected');
  async function present(source, expected) {
    const session = await json('/api/oid4vp/initiate', { credentialType: 'AgeCredential', protocol: 'openid4vp-1.0' });
    const requestObject = await json('/api/oid4vp/request/' + session.sessionId);
    const selected = source.disclosures.filter(d => JSON.parse(Buffer.from(d, 'base64url').toString())[1] === 'age_over_18');
    assert.equal(selected.length, 1);
    const sdJwt = source.issuerJwt + '~' + selected.join('~') + '~';
    const kb = await new SignJWT({ nonce: requestObject.nonce, sd_hash: createHash('sha256').update(sdJwt).digest('base64url') })
      .setAudience(requestObject.client_id).setIssuedAt().setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).sign(source.pair.privateKey);
    const body = { state: session.sessionId, vp_token: { credential: [sdJwt + kb] } };
    const response = await request('/api/oid4vp/response/' + session.sessionId, body); assert.equal(response.status, expected);
    assert.equal((await request('/api/oid4vp/session/' + session.sessionId)).status, 401);
    const result = await json('/api/oid4vp/session/' + session.sessionId, undefined, session.readToken);
    if (expected === 200) { assert.equal(result.status, 'verified'); assert.deepEqual(result.claims, { age_over_18: true }); assert.equal((await request('/api/oid4vp/response/' + session.sessionId, body)).status, 409); }
    else { assert.equal(result.status, 'initiated'); assert.equal(result.claims, null); }
    return result;
  }
  const result = await present(issued, 200);
  passed('Selective presentation verified', { disclosedClaims: result.claims, rawCredentialRecorded: false });
  passed('Presentation replay and unauthenticated result access rejected');
  async function statusBit(source) {
    const status = source.payload.credentialStatus; const url = new URL(status.statusListCredential); assert.equal(url.origin, origin);
    const response = await request(url.pathname); assert.equal(response.status, 200);
    const { payload } = await jwtVerify(await response.text(), keys, { algorithms: ['ES256'], issuer: readiness.issuer.did });
    const bytes = gunzipSync(Buffer.from(payload.credentialSubject.encodedList, 'base64url'));
    const index = Number(status.statusListIndex); return (bytes[Math.floor(index / 8)] >> (7 - (index % 8))) & 1;
  }
  assert.equal(await statusBit(issued), 0);
  assert.equal((await json('/admin/revoke', { credentialId: issued.payload.jti, reason: 'Synthetic local walkthrough' }, adminApiKey)).success, true);
  assert.equal(await statusBit(issued), 1); await present(issued, 401);
  passed('Revocation published and fresh revoked presentation rejected', { credentialId: issued.payload.jti });
  const replacement = await issue('walkthrough-adult'); await present(replacement, 200); assert.equal(await statusBit(replacement), 0);
  passed('Replacement credential issued and verified', { credentialId: replacement.payload.jti, recordedState: 'active' });
  report.outcome = 'PASS';
  console.log('Synthetic walkthrough PASS. Inspect active and revoked records at ' + origin + '/console/monitor.');
} catch (error) {
  // Never serialize fetch/assertion objects: they may contain bearer tokens or signed credentials.
  report.steps.push({ step: 'Walkthrough failed', result: 'FAIL', detail: 'Check local startup, fixture configuration and protocol results; secret-bearing diagnostics are intentionally omitted.' });
  console.error('Synthetic walkthrough failed. Start npm run walkthrough and check the isolated fixture configuration.'); process.exitCode = 1;
} finally {
  report.completedAt = new Date().toISOString(); writeFileSync(reportPath, JSON.stringify(report, null, 2), { mode: 0o600 });
  console.log('Redacted report: ' + reportPath);
}
