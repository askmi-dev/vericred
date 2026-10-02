import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify } from 'jose';
import { mkdirSync, existsSync, writeFileSync, rmSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';
import { getIssuerKeyPair } from '../../keys/manager.js';

describe('Admin API - Revocation Endpoints', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  let holderKeys: { privateKey: import('jose').KeyLike; publicKey: import('jose').KeyLike };

  beforeAll(async () => {
    const tempDir = './src/revocation/__tests__/temp-data-admin';
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
    mkdirSync(tempDir, { recursive: true });

    const mockHolders = [
      { id: 'admin-test-holder', email: 'admin-test@example.com', firstName: 'Admin', lastName: 'Test', dateOfBirth: '1990-01-01' }
    ];
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify(mockHolders, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['ISSUER_URL'] = 'http://localhost:3517';
    process.env['PORT'] = '3517';
    serverUrl = 'http://localhost:3517';

    holderKeys = await generateKeyPair('ES256');

    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  afterEach(async () => {
    // Clean up test credentials
    try {
      const res = await fetch(`${serverUrl}/admin/api/credentials`, {
        headers: { 'Authorization': `Bearer ${adminApiKey}` }
      });
      if (res.ok) {
        const creds = await res.json();
        for (const cred of creds) {
          if (cred.credentialId && cred.credentialId.includes('admin-test')) {
            await fetch(`${serverUrl}/admin/api/credentials/${cred.credentialId}/revoke`, {
              method: 'POST',
              headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${adminApiKey}`
              },
              body: JSON.stringify({ reason: 'Test cleanup' })
            });
          }
        }
      }
    } catch {
      // Ignore cleanup errors
    }
  });

  it('GET /admin/api/credentials returns list with PII masking by default', async () => {
    // Ensure PII_ADMIN_MODE is not set
    const originalPiiMode = process.env['PII_ADMIN_MODE'];
    delete process.env['PII_ADMIN_MODE'];

    const res = await fetch(`${serverUrl}/admin/api/credentials`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(res.status).toBe(200);
    const creds = await res.json() as any[];
    
    // Check that emails are masked
    for (const cred of creds) {
      if (cred.holderEmail) {
        // Should be masked
        expect(cred.holderEmail).toMatch(/^\w{2}\*\*\*@/);
        // Should NOT contain full email
        expect(cred.holderEmail).not.toContain('@example.com');
      }
    }

    // Restore original
    if (originalPiiMode) process.env['PII_ADMIN_MODE'] = originalPiiMode;
  });

  it('GET /admin/api/credentials with PII_ADMIN_MODE=true returns unmasked data', async () => {
    // Set PII_ADMIN_MODE
    process.env['PII_ADMIN_MODE'] = 'true';

    // First issue a credential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'admin-test-holder', credentialType: 'AgeCredential' })
    });
    
    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    const preAuthCode = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': preAuthCode })
    });
    
    const tokenData = await tokenRes.json() as any;
    const { access_token, c_nonce } = tokenData;

    const proofJwt = await new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(holderKeys.publicKey) })
      .sign(holderKeys.privateKey);

    await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } })
    });

    // Now fetch credentials with PII mode enabled
    const res = await fetch(`${serverUrl}/admin/api/credentials`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(res.status).toBe(200);
    const creds = await res.json() as any[];
    
    // Should have at least one credential
    expect(creds.length).toBeGreaterThan(0);
    
    // Check that emails are NOT masked
    const found = creds.find(c => c.holderEmail === 'admin-test@example.com');
    expect(found).toBeDefined();

    // Clean up
    delete process.env['PII_ADMIN_MODE'];
  });

  it('GET /admin/api/credentials?search= filters by search query', async () => {
    // Issue a credential first
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'admin-test-holder', credentialType: 'AgeCredential' })
    });
    
    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    const preAuthCode = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': preAuthCode })
    });
    
    const tokenData = await tokenRes.json() as any;
    const { access_token, c_nonce } = tokenData;

    const proofJwt = await new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(holderKeys.publicKey) })
      .sign(holderKeys.privateKey);

    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } })
    });
    
    const credData = await credentialRes.json() as any;
    const rawCredential = credData.credential as string;
    const parts = rawCredential.split('~');
    const baseJwt = parts[0]!;
    const { publicKey } = await getIssuerKeyPair();
    const { payload } = await jwtVerify(baseJwt, publicKey);
    const credentialId = payload.jti as string;

    // Now search for this specific credential
    const searchRes = await fetch(`${serverUrl}/admin/api/credentials?search=${encodeURIComponent(credentialId)}`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(searchRes.status).toBe(200);
    const results = await searchRes.json() as any[];
    
    // Should find at least one credential
    expect(results.length).toBeGreaterThan(0);
    
    // Should find our specific credential
    const found = results.some(c => c.credentialId === credentialId);
    expect(found).toBe(true);
  });

  it('GET /admin/api/credentials?status=revoked filters by revoked status', async () => {
    // Issue and revoke a credential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'admin-test-holder', credentialType: 'AgeCredential' })
    });
    
    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    const preAuthCode = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': preAuthCode })
    });
    
    const tokenData = await tokenRes.json() as any;
    const { access_token, c_nonce } = tokenData;

    const proofJwt = await new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(holderKeys.publicKey) })
      .sign(holderKeys.privateKey);

    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } })
    });
    
    const credData = await credentialRes.json() as any;
    const rawCredential = credData.credential as string;
    const parts = rawCredential.split('~');
    const baseJwt = parts[0]!;
    const { publicKey } = await getIssuerKeyPair();
    const { payload } = await jwtVerify(baseJwt, publicKey);
    const credentialId = payload.jti as string;

    // Revoke it
    await fetch(`${serverUrl}/admin/api/credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ reason: 'Test status filter' })
    });

    // Filter by revoked
    const revokedRes = await fetch(`${serverUrl}/admin/api/credentials?status=revoked`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(revokedRes.status).toBe(200);
    const revokedCreds = await revokedRes.json() as any[];
    
    // All should be revoked
    expect(revokedCreds.every(c => c.revoked === true)).toBe(true);

    // Filter by active
    const activeRes = await fetch(`${serverUrl}/admin/api/credentials?status=active`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(activeRes.status).toBe(200);
    const activeCreds = await activeRes.json() as any[];
    
    // All should be active (not revoked)
    expect(activeCreds.every(c => c.revoked === false)).toBe(true);
    
    // The revoked credential should NOT be in active list
    expect(activeCreds.some(c => c.credentialId === credentialId)).toBe(false);
  });

  it('POST /admin/api/credentials/:id/revoke revokes credential and returns success', async () => {
    // Issue a credential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'admin-test-holder', credentialType: 'AgeCredential' })
    });
    
    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    const preAuthCode = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': preAuthCode })
    });
    
    const tokenData = await tokenRes.json() as any;
    const { access_token, c_nonce } = tokenData;

    const proofJwt = await new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(holderKeys.publicKey) })
      .sign(holderKeys.privateKey);

    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } })
    });
    
    const credData = await credentialRes.json() as any;
    const rawCredential = credData.credential as string;
    const parts = rawCredential.split('~');
    const baseJwt = parts[0]!;
    const { publicKey } = await getIssuerKeyPair();
    const { payload } = await jwtVerify(baseJwt, publicKey);
    const credentialId = payload.jti as string;

    // Revoke it
    const revokeRes = await fetch(`${serverUrl}/admin/api/credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ reason: 'Test revocation' })
    });
    
    expect(revokeRes.status).toBe(200);
    const result = await revokeRes.json() as any;
    
    expect(result.success).toBe(true);
    expect(result.message).toBe('Credential revoked');
    expect(result.credential).toBeDefined();
    // Check that the credential is marked as revoked
    expect(result.credential.revoked).toBe(true);

    // Try to revoke again - should fail
    const revokeAgainRes = await fetch(`${serverUrl}/admin/api/credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ reason: 'Test double revoke' })
    });
    
    expect(revokeAgainRes.status).toBe(200);
    const result2 = await revokeAgainRes.json() as any;
    
    expect(result2.success).toBe(false);
    expect(result2.message).toBe('Already revoked');
  });

  it('GET /admin/api/credentials/:id returns single credential', async () => {
    // Issue a credential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'admin-test-holder', credentialType: 'AgeCredential' })
    });
    
    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    const preAuthCode = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': preAuthCode })
    });
    
    const tokenData = await tokenRes.json() as any;
    const { access_token, c_nonce } = tokenData;

    const proofJwt = await new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(holderKeys.publicKey) })
      .sign(holderKeys.privateKey);

    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } })
    });
    
    const credData = await credentialRes.json() as any;
    const rawCredential = credData.credential as string;
    const parts = rawCredential.split('~');
    const baseJwt = parts[0]!;
    const { publicKey } = await getIssuerKeyPair();
    const { payload } = await jwtVerify(baseJwt, publicKey);
    const credentialId = payload.jti as string;

    // Get single credential
    const singleRes = await fetch(`${serverUrl}/admin/api/credentials/${encodeURIComponent(credentialId)}`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(singleRes.status).toBe(200);
    const cred = await singleRes.json() as any;
    
    expect(cred.credentialId).toBe(credentialId);
    expect(cred.holderEmail).toBeDefined();

    // Not found case
    const notFoundRes = await fetch(`${serverUrl}/admin/api/credentials/non-existent-credential-id`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(notFoundRes.status).toBe(404);
  });

  it('unauthorized access to admin endpoints fails with 401', async () => {
    // Try to access without auth
    const res = await fetch(`${serverUrl}/admin/api/credentials`, {
      headers: { 'Content-Type': 'application/json' }
    });
    
    expect([401, 403]).toContain(res.status);

    // Try to revoke without auth
    const revokeRes = await fetch(`${serverUrl}/admin/api/credentials/some-id/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: 'Unauthorized test' })
    });
    
    expect([401, 403]).toContain(revokeRes.status);
  });
});
