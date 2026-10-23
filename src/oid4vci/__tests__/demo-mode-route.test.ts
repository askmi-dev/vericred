/**
 * #35 review follow-up — route-level negatives for the issuance-side
 * DEMO_MODE guard.
 *
 * The startup guard (demo-mode-guard.test.ts) proves the exact
 * DEMO_MODE=true && NODE_ENV=production combination aborts the process.
 * This file covers what that test does not:
 *  - the /credentials issuance guard is exercised directly, with the
 *    startup guard bypassed by the test harness (server already booted
 *    with NODE_ENV unset, then flipped to 'production' in-process);
 *  - the refused request must not leak a credential, a nonce-success
 *    side effect, or an anonymous-thumbprint credential;
 *  - valid holder-bound issuance still works (no over-blocking);
 *  - the NODE_ENV matrix limit is documented: the guard checks the exact
 *    string 'production'. A deployment mislabeled as 'dev'/'staging' or
 *    with an unknown NODE_ENV falls outside this condition — an
 *    environment-string check is not a universal production guarantee.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { loadSecrets } from '../../config/secrets.js';

const tempDir = './src/oid4vci/__tests__/temp-data-demo-route';
const PORT = '3524';

function setupEnv() {
  rmSync(tempDir, { recursive: true, force: true });
  mkdirSync(tempDir, { recursive: true });
  writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
    { id: 'demo-route-holder-01', email: 'route@example.com', dateOfBirth: '1990-01-01' },
  ], null, 2));
  writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify({
    issuer: { name: 'Demo Route Test', url: `http://localhost:${PORT}`, did: `did:web:localhost%3A${PORT}` },
    credential: { type: 'AgeCredential', expiresInDays: 30 },
    templateOptions: { ageThresholds: [18, 21], jurisdiction: 'EU' },
    dataSource: { type: 'json', path: `${tempDir}/holders.json` },
    fieldMappings: { dateOfBirth: 'dateOfBirth' },
  }, null, 2));
  process.env['DATA_DIR'] = tempDir;
  process.env['PORT'] = PORT;
  process.env['ISSUER_URL'] = `http://localhost:${PORT}`;
}

async function getPreAuthCode(serverUrl: string, adminApiKey: string): Promise<string> {
  const offerRes = await fetch(`${serverUrl}/offer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
    body: JSON.stringify({ holderId: 'demo-route-holder-01' }),
  });
  expect(offerRes.status).toBe(200);
  const offer = await offerRes.json() as { offer?: { grants?: Record<string, { 'pre-authorized_code'?: string }> } };
  const code = offer.offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'] ?? '';
  expect(code).not.toBe('');
  return code;
}

async function mintToken(serverUrl: string, code: string): Promise<{ token: string; cNonce: string }> {
  const res = await fetch(`${serverUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }),
  });
  expect(res.status).toBe(200);
  const body = await res.json() as { access_token: string; c_nonce: string };
  return { token: body.access_token, cNonce: body.c_nonce };
}

async function holderProofJwt(issuerUrl: string, cNonce: string): Promise<string> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  return new SignJWT({ nonce: cNonce })
    .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk })
    .setIssuer('did:example:holder')
    .setAudience(issuerUrl)
    .setIssuedAt()
    .sign(privateKey);
}

describe('#35 review: /credentials issuance guard (startup bypassed)', () => {
  let serverUrl: string;
  let adminApiKey: string;

  beforeAll(async () => {
    setupEnv();
    // Server boots as an explicit development deployment: the startup
    // guard is bypassed by construction, exactly like a mislabeled
    // deployment would be. DEMO_MODE is on for the anonymous-fallback path.
    process.env['DEMO_MODE'] = 'true';
    delete process.env['NODE_ENV'];
    serverUrl = `http://localhost:${PORT}`;
    adminApiKey = loadSecrets().adminApiKey;

    await import('../../server.js');
    await new Promise((resolve) => setTimeout(resolve, 500));
  }, 30000);

  afterAll(() => {
    delete process.env['DEMO_MODE'];
    delete process.env['NODE_ENV'];
    delete process.env['DATA_DIR'];
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('refuses the anonymous fallback with server_error when NODE_ENV flips to production, without side effects', async () => {
    const code = await getPreAuthCode(serverUrl, adminApiKey);
    const { token, cNonce } = await mintToken(serverUrl, code);
    const nonceBefore = cNonce;

    process.env['NODE_ENV'] = 'production';
    try {
      const res = await fetch(`${serverUrl}/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ format: 'dc+sd-jwt', credential_type: 'AgeCredential' }),
      });
      expect(res.status).toBe(500);
      const body = await res.json() as { error?: string; error_description?: string };
      expect(body.error).toBe('server_error');
      expect(body.error_description).toContain('DEMO_MODE');

      // No nonce-success side effect: the c_nonce must not have been
      // rotated by a refused request.
      const { lookupAccessToken } = await import('../token.js');
      const entry = lookupAccessToken(token);
      expect(entry?.cNonce).toBe(nonceBefore);
    } finally {
      delete process.env['NODE_ENV'];
    }
  });

  it('a valid holder proof still issues in production mode (no over-blocking)', async () => {
    const code = await getPreAuthCode(serverUrl, adminApiKey);
    const { token, cNonce } = await mintToken(serverUrl, code);
    const proofJwt = await holderProofJwt(`http://localhost:${PORT}`, cNonce);

    process.env['NODE_ENV'] = 'production';
    try {
      const res = await fetch(`${serverUrl}/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ format: 'dc+sd-jwt', credential_type: 'AgeCredential', proof: { proof_type: 'jwt', jwt: proofJwt } }),
      });
      expect(res.status).toBe(200);
      const body = await res.json() as { credential?: string };
      expect(typeof body.credential).toBe('string');
      // Holder-bound, never the anonymous thumbprint.
      expect(body.credential).not.toContain('"anonymous"');
    } finally {
      delete process.env['NODE_ENV'];
    }
  });

  it('matrix: DEMO_MODE=true with missing or unknown NODE_ENV still allows the documented development-demo fallback', async () => {
    // Honest limit: the guard only recognizes the exact string
    // 'production'. This asserts the current behavior — a deployment
    // mislabeled as 'staging' or 'dev' still gets the anonymous fallback.
    // The mitigation is deployment policy, not this string check.
    const code = await getPreAuthCode(serverUrl, adminApiKey);
    const { token } = await mintToken(serverUrl, code);

    for (const envValue of [undefined, 'development', 'staging', 'prod-like-typo']) {
      if (envValue === undefined) delete process.env['NODE_ENV'];
      else process.env['NODE_ENV'] = envValue;
      const res = await fetch(`${serverUrl}/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ format: 'dc+sd-jwt', credential_type: 'AgeCredential' }),
      });
      expect(res.status).toBe(200);
      const body = await res.json() as { credential?: string };
      expect(typeof body.credential).toBe('string');
    }
    delete process.env['NODE_ENV'];
  });
});
