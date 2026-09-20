import { isDeepStrictEqual } from 'node:util';
import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { decodeProtectedHeader, jwtVerify } from 'jose';

const input = process.argv[2];
const expectedFingerprint = process.env.EUDI_ISSUER_CERT_SHA256;
try {
  assert(input && expectedFingerprint, 'Usage: EUDI_ISSUER_CERT_SHA256=<DER SHA256 hex> node scripts/https-preflight.mjs https://your-host');
  assert(/^(?:[0-9a-f]{64}|(?:[0-9a-f]{2}:){31}[0-9a-f]{2})$/i.test(expectedFingerprint), 'Expected a SHA256 certificate fingerprint');
  const origin = new URL(input);
  assert(origin.protocol === 'https:' && origin.pathname === '/' && !origin.search && !origin.hash && !origin.username && !origin.password, 'A root HTTPS origin is required');
  assert.notEqual(process.env.NODE_TLS_REJECT_UNAUTHORIZED, '0', 'TLS verification must remain enabled');
  const base = origin.origin;
  async function request(path, options = {}) {
    const response = await fetch(base + path, { ...options, redirect: 'error', signal: AbortSignal.timeout(15000) });
    assert(response.headers.get('strict-transport-security'), 'Missing HSTS');
    return response;
  }
  async function body(response) {
    assert(response.body, 'Missing response body');
    const reader = response.body.getReader();
    const chunks = []; let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        assert(size <= 1024 * 1024, 'Response exceeds preflight size limit');
        chunks.push(Buffer.from(value));
      }
      return Buffer.concat(chunks).toString('utf8');
    } finally { await reader.cancel(); }
  }
  const health = await request('/health'); assert.equal(health.status, 200);
  const metadataResponse = await request('/.well-known/openid-credential-issuer', { headers: { Accept: 'application/jwt' } });
  assert.equal(metadataResponse.status, 200);
  assert.match(metadataResponse.headers.get('content-type') ?? '', /^application\/jwt/);
  const token = await body(metadataResponse);
  const header = decodeProtectedHeader(token);
  assert(Array.isArray(header.x5c) && header.x5c[0], 'Missing metadata signing certificate');
  const certificate = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
  assert.equal(createHash('sha256').update(certificate.raw).digest('hex'), expectedFingerprint.replaceAll(':', '').toLowerCase(), 'Issuer certificate does not match the independently provided pin');
  assert(Date.now() >= Date.parse(certificate.validFrom) && Date.now() < Date.parse(certificate.validTo), 'Signing certificate validity');
  const metadata = (await jwtVerify(token, certificate.publicKey, { algorithms: ['ES256'], typ: 'openidvci-issuer-metadata+jwt', issuer: base, subject: base, requiredClaims: ['iat', 'exp'] })).payload;
  const now = Math.floor(Date.now() / 1000);
  assert(Number.isSafeInteger(metadata.iat) && Number.isSafeInteger(metadata.exp)
    && metadata.iat <= now + 30 && metadata.iat >= now - 330
    && metadata.exp > metadata.iat && metadata.exp - metadata.iat <= 300, 'Metadata freshness');
  assert.equal(metadata.credential_issuer, base);
  assert.equal(metadata.credential_endpoint, base + '/credentials');
  assert.equal(metadata.nonce_endpoint, base + '/nonce');
  assert.equal(metadata.credential_request_encryption?.encryption_required, true);
  assert.equal(metadata.credential_response_encryption?.encryption_required, true);
  const configurations = metadata.credential_configurations_supported;
  assert(configurations && typeof configurations === 'object' && !Array.isArray(configurations)
    && Object.keys(configurations).length > 0, 'No credential configurations advertised');
  const assurance = new Set(['iso_18045_high', 'iso_18045_moderate', 'iso_18045_enhanced-basic', 'iso_18045_basic']);
  for (const configuration of Object.values(configurations)) {
    assert.equal(configuration.format, 'dc+sd-jwt', 'Credential format');
    assert(typeof configuration.vct === 'string' && configuration.vct.length > 0, 'Missing VCT');
    const proof = configuration.proof_types_supported?.jwt;
    assert.deepEqual(proof?.proof_signing_alg_values_supported, ['ES256'], 'Proof algorithms');
    const requirements = proof.key_attestations_required;
    assert(requirements, 'Missing key attestation requirements');
    for (const field of ['key_storage', 'user_authentication']) {
      assert(Array.isArray(requirements[field]) && requirements[field].length > 0
        && requirements[field].every(value => assurance.has(value)), 'Invalid attestation assurance requirements');
    }
    assert(Number.isSafeInteger(requirements.preferred_key_storage_status_period)
      && requirements.preferred_key_storage_status_period > 0, 'Invalid key storage status period');
  }
  const plain = await request('/.well-known/openid-credential-issuer', { headers: { Accept: 'application/json' } });
  assert.equal(plain.status, 200);
  assert.match(plain.headers.get('content-type') ?? '', /^application\/json(?:;|$)/i);
  const { iss, sub, iat, exp, ...signedDiscovery } = metadata;
  assert(isDeepStrictEqual(JSON.parse(await body(plain)), signedDiscovery), 'Signed and unsigned metadata disagree');
  const unauthorized = await request('/credentials', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(unauthorized.status, 401);
  const nonce = await request('/nonce', { method: 'POST' });
  assert.equal(nonce.status, 200); assert.match(nonce.headers.get('cache-control') ?? '', /no-store/);
  const nonceValue = JSON.parse(await body(nonce)).c_nonce;
  assert(typeof nonceValue === 'string' && nonceValue.length > 0, 'Missing nonce');
  console.log(JSON.stringify({ status: 'PASS', scope: 'HTTPS transport and pinned metadata consistency preflight', origin: base,
    independentWalletAcceptance: 'NOT RUN', registrationPolicyOnAcceptance: 'NOT RUN', providerTrustAcceptance: 'NOT RUN', checkedAt: new Date().toISOString() }, null, 2));
} catch (error) {
  console.error('HTTPS preflight failed: ' + error.message);
  process.exitCode = 1;
}
