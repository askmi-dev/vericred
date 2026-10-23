/**
 * #26 — Art. 6a provenance logging, E2E wiring test.
 *
 * Full pre-auth flow: POST /offer → POST /token → POST /credentials with a
 * holder proof, then assert a provenance record was persisted that joins
 * to the issued credential's jti, with only a hashed identifier.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, decodeJwt, calculateJwkThumbprint } from 'jose';
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';

const TEMP = './src/oid4vci/__tests__/temp-data-prov';
const PORT = '3523';

describe('#26: provenance wiring — offer → token → credentials', () => {
  let serverUrl: string;
  let holderKeys: { privateKey: import('jose').KeyLike; publicKey: import('jose').KeyLike };

  beforeAll(async () => {
    if (existsSync(TEMP)) rmSync(TEMP, { recursive: true, force: true });
    mkdirSync(TEMP, { recursive: true });
    writeFileSync(`${TEMP}/holders.json`, JSON.stringify([
      { id: 'prov-holder-01', email: 'prov@example.com', dateOfBirth: '1990-01-01' }
    ], null, 2));
    writeFileSync(`${TEMP}/vericred.config.json`, JSON.stringify({
      issuer: { name: 'Prov Test', url: `http://localhost:${PORT}`, did: `did:web:localhost%3A${PORT}` },
      credential: { type: 'AgeCredential', expiresInDays: 30 },
      templateOptions: { ageThresholds: [18, 21], jurisdiction: 'EU' },
      dataSource: { type: 'json', path: `${TEMP}/holders.json` },
      fieldMappings: { dateOfBirth: 'dateOfBirth' }
    }, null, 2));
    process.env['DATA_DIR'] = TEMP;
    process.env['PORT'] = PORT;
    process.env['ISSUER_URL'] = `http://localhost:${PORT}`;
    delete process.env['DEMO_MODE'];
    serverUrl = `http://localhost:${PORT}`;
    holderKeys = await generateKeyPair('ES256');
    await import('../../server.js');
    await new Promise(r => setTimeout(r, 500));
  }, 30000);

  afterAll(() => {
    rmSync(TEMP, { recursive: true, force: true });
  });

  it('persists an Art. 6a provenance record joining to the issued jti, identifier hashed', async () => {
    const adminApiKey = loadSecrets().adminApiKey;
    // 1. Offer
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'prov-holder-01' })
    });
    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    const preAuthCode = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    // 2. Token
    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': preAuthCode })
    });
    expect(tokenRes.status).toBe(200);
    const tokenData = await tokenRes.json() as any;

    // 3. Holder proof
    const publicJwk = await exportJWK(holderKeys.publicKey);
    const proof = await new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: tokenData.c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
      .sign(holderKeys.privateKey);

    // 4. Credentials
    const credRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${tokenData.access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proof } })
    });
    expect(credRes.status).toBe(200);
    const credData = await credRes.json() as any;
    // SD-JWT: "<jwt>~<disclosure>..." — decode the JWT segment only
    const jti = decodeJwt(credData.credential.split('~')[0]).jti as string;
    expect(jti).toMatch(/^urn:uuid:/);

    // 5. Provenance record persisted and joins to jti
    const provPath = `${TEMP}/provenance/issuance.jsonl`;
    expect(existsSync(provPath)).toBe(true);
    const records = readFileSync(provPath, 'utf8').trim().split('\n').map(l => JSON.parse(l));
    const rec = records.find((r: any) => r.credentialId === jti);
    expect(rec).toBeDefined();
    expect(rec!.credentialType).toBe('AgeCredential');
    expect(rec!.source.connectorType).toBe('json');
    expect(rec!.lookup.identifierHash).toMatch(/^[0-9a-f]{64}$/);
    // Raw identifier never persisted
    expect(readFileSync(provPath, 'utf8')).not.toContain('prov-holder-01');
    expect(rec!.verification.mode).toBe('authoritative-source');
    expect(rec!.issuerDid).toContain('did:web');
  }, 20000);
});
