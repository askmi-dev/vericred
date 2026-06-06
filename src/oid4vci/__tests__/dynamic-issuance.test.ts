import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, decodeJwt } from 'jose';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';
import { decodeDisclosure } from '../../sdjwt/disclosures.js';

describe('Task 4: Dynamic Issuance and Smart Mapping E2E Integration', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  let holderKeys: { privateKey: import('jose').KeyLike; publicKey: import('jose').KeyLike };

  beforeAll(async () => {
    // Isolated environment setup
    const tempDir = './src/oid4vci/__tests__/temp-data';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });

    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
      {
        id: 'holder-test-01',
        email: 'john.doe@example.com',
        dateOfBirth: '1990-01-01',
        givenName: 'John',
        familyName: 'Doe',
        organization: 'ACME Corp',
        role: 'Software Engineer',
        department: 'R&D'
      }
    ], null, 2));

    writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify({
      issuer: {
        name: 'VeriCred Test Issuer',
        url: 'http://localhost:3513',
        did: 'did:web:localhost%3A3513'
      },
      credential: {
        type: 'AgeCredential',
        expiresInDays: 30
      },
      templateOptions: {
        ageThresholds: [18, 21],
        jurisdiction: 'EU'
      },
      dataSource: {
        type: 'json',
        path: `${tempDir}/holders.json`
      },
      fieldMappings: {
        dateOfBirth: 'dateOfBirth'
      }
    }, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = '3513';
    process.env['ISSUER_URL'] = 'http://localhost:3513';
    serverUrl = 'http://localhost:3513';

    holderKeys = await generateKeyPair('ES256');

    // Import and spin up the server
    await import('../../server.js');

    // Wait for Express server to start listening
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('supports the default credential type (AgeCredential) if not specified', async () => {
    const res = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ holderId: 'holder-test-01' })
    });

    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.offer.credential_configuration_ids).toEqual(['AgeCredential']);
    expect(data.offer_uri).toContain('openid-credential-offer://');
  });

  it('rejects the offer if the template mappings are invalid (dry-run check)', async () => {
    // EmployeeCredential requires given_name, family_name, organization, role.
    // If we request a fake credential type or one that fails mapping, it should fail.
    const res = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ holderId: 'holder-test-01', credentialType: 'RogueCredential' })
    });

    expect(res.status).toBe(400);
    const data = await res.json() as any;
    expect(data.error).toContain('Unknown credential type: "RogueCredential"');
  });

  it('executes a complete pre-auth and issuance flow for a dynamically requested type (EmployeeCredential) with smart mapping fallback', async () => {
    // 1. Request an offer for EmployeeCredential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({
        holderId: 'holder-test-01',
        credentialType: 'EmployeeCredential'
      })
    });

    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    expect(offerData.offer.credential_configuration_ids).toEqual(['EmployeeCredential']);

    const preAuthGrant = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
    const preAuthCode = preAuthGrant['pre-authorized_code'];
    expect(preAuthCode).toBeTruthy();

    // 2. Exchange the pre-authorized code at /token
    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthCode
      })
    });

    expect(tokenRes.status).toBe(200);
    const tokenData = await tokenRes.json() as any;
    const accessToken = tokenData.access_token;
    const cNonce = tokenData.c_nonce;
    expect(accessToken).toBeTruthy();
    expect(cNonce).toBeTruthy();

    // 3. Construct a standard Holder Proof JWT
    const publicJwk = await exportJWK(holderKeys.publicKey);
    const proofJwt = await new SignJWT({
      aud: serverUrl,
      iat: Math.floor(Date.now() / 1000),
      nonce: cNonce
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
      .sign(holderKeys.privateKey);

    // 4. Issue the credential at /credentials using the token
    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${accessToken}`
      },
      body: JSON.stringify({
        format: 'dc+sd-jwt',
        proof: {
          proof_type: 'jwt',
          jwt: proofJwt
        }
      })
    });

    expect(credentialRes.status).toBe(200);
    const credData = await credentialRes.json() as any;
    expect(credData.credential).toBeTruthy();
    expect(credData.format).toBe('dc+sd-jwt');

    // 5. Deconstruct and verify the issued SD-JWT-VC
    const credentialString = credData.credential as string;
    const parts = credentialString.split('~');
    const jwtPart = parts[0];
    expect(jwtPart).toBeTruthy();

    // Decode signed JWT header and payload
    const claims = decodeJwt(jwtPart) as any;
    expect(claims.vct).toBe('EmployeeCredential'); // Purpose limitation enforced!
    expect(claims.iss).toBe('did:web:localhost%3A3513');
    expect(claims.cnf).toEqual({ jkt: expect.any(String) });

    // Verify selective disclosure hashes exist in the payload
    expect(claims._sd).toBeInstanceOf(Array);
    expect(claims._sd!.length).toBeGreaterThan(0);

    // 6. Decode disclosures and verify smart-mapped claims
    const disclosures = parts.slice(1, -1); // discard signed JWT and trailing empty string
    expect(disclosures.length).toBeGreaterThan(0);

    const decryptedClaims: Record<string, any> = {};
    for (const d of disclosures) {
      const [_salt, name, value] = decodeDisclosure(d);
      decryptedClaims[name] = value;
    }

    // Verify smart-mapped and directly matched fields:
    // "given_name" was mapped from "givenName" (John) via smart fallback normalization
    expect(decryptedClaims.given_name).toBe('John');
    // "family_name" was mapped from "familyName" (Doe) via smart fallback normalization
    expect(decryptedClaims.family_name).toBe('Doe');
    // "organization" matched directly (ACME Corp)
    expect(decryptedClaims.organization).toBe('ACME Corp');
    // "role" matched directly (Software Engineer)
    expect(decryptedClaims.role).toBe('Software Engineer');
    // Optional "department" matched directly (R&D)
    expect(decryptedClaims.department).toBe('R&D');
  });
});
