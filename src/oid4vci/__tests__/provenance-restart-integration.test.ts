/**
 * #36 + #37 combined-head integration gate (review requirement).
 *
 * Both branches change offer/token state, so separate branch totals do
 * not prove the composition. This test runs the full flow on the
 * combined head:
 *   consent → offer (pre-auth code persisted) → simulated restart →
 *   token → issuance
 * and asserts that the provenance fields survive the restart and the
 * consumption, and that the issued credential's jti joins to the
 * persisted Art. 6a audit record.
 *
 * Honest limits: the "restart" is a fresh FileOfferStore over the same
 * DATA_DIR files, not a real process kill; the server in this test keeps
 * its in-process store, so the restarted store is inspected read-only
 * (noLock) rather than serving traffic.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { generateKeyPair, exportJWK, SignJWT, decodeJwt } from 'jose';
import { loadSecrets } from '../../config/secrets.js';

const tempDir = './src/oid4vci/__tests__/temp-data-combined';
const PORT = '3526';

describe('#36+#37 combined: consent → offer → restart → token → issuance', () => {
  let serverUrl: string;
  let adminApiKey: string;

  beforeAll(async () => {
    rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
      { id: 'combined-holder-01', email: 'combined@example.com', dateOfBirth: '1990-01-01', role: 'engineer',
        given_name: 'Anna', family_name: 'Beispiel', organization: 'Acme Corp', membershipType: 'premium' },
    ], null, 2));
    // MembershipCredential requires consent (consent-gate path)
    writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify({
      issuer: { name: 'Combined Test', url: `http://localhost:${PORT}`, did: `did:web:localhost%3A${PORT}` },
      credential: { type: 'MembershipCredential', expiresInDays: 30 },
      templateOptions: { ageThresholds: [18, 21] },
      dataSource: { type: 'json', path: `${tempDir}/holders.json` },
      fieldMappings: { organization: 'organization', membershipType: 'membershipType' },
    }, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = PORT;
    process.env['ISSUER_URL'] = `http://localhost:${PORT}`;
    process.env['PROVENANCE_HASH_KEY'] = 'combined-test-key';
    serverUrl = `http://localhost:${PORT}`;
    adminApiKey = loadSecrets().adminApiKey;

    await import('../../server.js');
    await new Promise((resolve) => setTimeout(resolve, 500));
  }, 30000);

  afterAll(() => {
    delete process.env['PROVENANCE_HASH_KEY'];
    delete process.env['DATA_DIR'];
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('keeps provenance and approved claims across a restart between offer and token', async () => {
    // 1. Offer (consent-gated template → consent record first)
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'combined-holder-01' }),
    });
    expect(offerRes.status).toBe(200);
    const offer = await offerRes.json() as { consent_required?: boolean; consent_url?: string; offer?: { grants?: Record<string, { 'pre-authorized_code'?: string }> } };

    let code: string;
    if (offer.consent_required) {
      // 2. Holder approves the consent snapshot
      const consentId = offer.consent_url!.split('/consent/')[1];
      const decideRes = await fetch(`${serverUrl}/consent/${consentId}/decide`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved: true }),
      });
      expect(decideRes.status).toBe(200);
      const decided = await decideRes.json() as { offer?: { grants?: Record<string, { 'pre-authorized_code'?: string }> } };
      code = decided.offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'] ?? '';
    } else {
      code = offer.offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'] ?? '';
    }
    expect(code).not.toBe('');

    // 3. Simulated restart: a fresh store over the same files must see
    // the pending code AND its provenance/claims payload.
    const { FileOfferStore } = await import('../state-store.js');
    const restarted = new FileOfferStore(tempDir, { noLock: true }); // server holds the lock
    const entry = restarted.takePreAuthCode(code);
    expect(entry).not.toBeNull();
    expect(entry!.provenance).toBeDefined();
    expect(entry!.provenance!.identifierHash).toMatch(/^[0-9a-f]{64}$/);
    expect(entry!.provenance!.connectorType).toBe('json');
    // The code is single-use even across the restart boundary: put it
    // back is NOT allowed — instead verify the live server can still
    // redeem it once (the restarted instance consumed its view only).
    expect(restarted.takePreAuthCode(code)).toBeNull();

    // 4. The live server redeems the same code via /token
    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }),
    });
    expect(tokenRes.status).toBe(200);
    const token = await tokenRes.json() as { access_token: string; c_nonce: string };

    // 5. Issuance with holder proof
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);
    const proofJwt = await new SignJWT({ nonce: token.c_nonce })
      .setProtectedHeader({ typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk })
      .setIssuer('did:example:holder')
      .setAudience(`http://localhost:${PORT}`)
      .setIssuedAt()
      .sign(privateKey);

    const credRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token.access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', credential_type: 'MembershipCredential', proof: { proof_type: 'jwt', jwt: proofJwt } }),
    });
    expect(credRes.status).toBe(200);
    const cred = await credRes.json() as { credential?: string };
    expect(typeof cred.credential).toBe('string');

    // 6. The jti of the issued credential joins to a persisted Art. 6a record
    const sdJwt = cred.credential!;
    const payloadB64 = sdJwt.split('~')[0];
    const payload = decodeJwt(payloadB64);
    const jti = payload.jti as string;
    expect(jti).toMatch(/^urn:uuid:/);

    const { readProvenance } = await import('../../provenance/store.js');
    const result = readProvenance();
    expect(result.absent).toBe(false);
    expect(result.unavailable).toBe(false);
    const record = result.records.find((r) => r.credentialId === jti);
    expect(record).toBeDefined();
    expect(record!.source.connectorType).toBe('json');
    expect(record!.consentGate.used).toBe(true);
    expect(record!.consentGate.claimsSnapshot).toBe(true);
    // Keyed hash, not plain sha256:
    const { createHash } = await import('crypto');
    const plain = createHash('sha256').update('combined-holder-01').digest('hex');
    expect(record!.lookup.identifierHash).not.toBe(plain);
  });
});
