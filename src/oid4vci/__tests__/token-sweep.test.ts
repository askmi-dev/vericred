import { describe, it, expect, beforeAll, vi } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';

describe('Pre-auth-code and access-token store eviction', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  let holderKeys: { privateKey: import('jose').KeyLike; publicKey: import('jose').KeyLike };

  beforeAll(async () => {
    const tempDir = './src/oid4vci/__tests__/temp-data-token-sweep';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });

    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
      { id: 'sweep-holder-01', dateOfBirth: '1990-01-01' },
    ], null, 2));

    writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify({
      issuer: {
        name: 'VeriCred Test Issuer',
        url: 'http://localhost:3522',
        did: 'did:web:localhost%3A3522',
      },
      credential: { type: 'AgeCredential', expiresInDays: 30 },
      templateOptions: { ageThresholds: [18, 21] },
      dataSource: { type: 'json', path: `${tempDir}/holders.json` },
      fieldMappings: { dateOfBirth: 'dateOfBirth' },
    }, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = '3522';
    process.env['ISSUER_URL'] = 'http://localhost:3522';
    serverUrl = 'http://localhost:3522';

    holderKeys = await generateKeyPair('ES256');

    await import('../../server.js');
    await new Promise((resolve) => setTimeout(resolve, 500));
  });

  it('sweeps a pre-authorized code that is never redeemed', async () => {
    const { sweepExpiredTokens } = await import('../token.js');

    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'sweep-holder-01' }),
    });
    expect(offerRes.status).toBe(200);
    // Deliberately never redeemed at /token.

    const realNow = Date.now;
    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => realNow() + 11 * 60 * 1000); // past the 10-min pre-auth TTL
    try {
      const swept = sweepExpiredTokens();
      expect(swept.preAuthCodes).toBeGreaterThanOrEqual(1);
    } finally {
      nowSpy.mockRestore();
    }
  });

  async function issueAccessToken(): Promise<{ access_token: string; c_nonce: string }> {
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'sweep-holder-01' }),
    });
    const offerData = (await offerRes.json()) as any;
    const preAuthCode =
      offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthCode,
      }),
    });
    expect(tokenRes.status).toBe(200);
    return (await tokenRes.json()) as any;
  }

  it('sweeps an access token past its 5-minute window', async () => {
    const { sweepExpiredTokens } = await import('../token.js');
    await issueAccessToken();

    const realNow = Date.now;
    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => realNow() + 6 * 60 * 1000); // past the 5-min access-token TTL
    try {
      const swept = sweepExpiredTokens();
      expect(swept.accessTokens).toBeGreaterThanOrEqual(1);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it('evicts an expired access token on lookup, independent of whether the sweep has run yet', async () => {
    const tokenData = await issueAccessToken();

    const realNow = Date.now;
    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => realNow() + 6 * 60 * 1000); // past the 5-min access-token TTL
    try {
      // No sweep call here -- this must fail on lookupAccessToken's own
      // expiry check alone.
      const publicJwk = await exportJWK(holderKeys.publicKey);
      const proofJwt = await new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: tokenData.c_nonce })
        .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
        .sign(holderKeys.privateKey);

      const credentialRes = await fetch(`${serverUrl}/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenData.access_token}` },
        body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } }),
      });
      expect(credentialRes.status).toBe(401);
    } finally {
      nowSpy.mockRestore();
    }
  });
});
