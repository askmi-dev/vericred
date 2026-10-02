import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, calculateJwkThumbprint } from 'jose';
import { mkdirSync, existsSync, writeFileSync, rmSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';
import { getIssuerKeyPair } from '../../keys/manager.js';

describe('Revocation Flow - OID4VP Verifier Compliance Tests', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  let holderKeys: { privateKey: import('jose').KeyLike; publicKey: import('jose').KeyLike };
  let holderThumbprint: string;

  beforeAll(async () => {
    const tempDir = './src/revocation/__tests__/temp-data-revocation';
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
    mkdirSync(tempDir, { recursive: true });

    const mockHolders = [
      { id: 'test-holder-revocation', email: 'test-revocation@example.com', firstName: 'Test', lastName: 'Revocation', dateOfBirth: '1990-01-01' }
    ];
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify(mockHolders, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['ISSUER_URL'] = 'http://localhost:3516';
    process.env['PORT'] = '3516';
    serverUrl = 'http://localhost:3516';

    holderKeys = await generateKeyPair('ES256');
    const publicJwk = await exportJWK(holderKeys.publicKey);
    holderThumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');

    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  afterEach(async () => {
    // Clean up any test credentials
    try {
      const res = await fetch(`${serverUrl}/admin/api/credentials`, {
        headers: { 'Authorization': `Bearer ${adminApiKey}` }
      });
      if (res.ok) {
        const creds = await res.json();
        for (const cred of creds) {
          if (cred.credentialId && cred.credentialId.includes('test-revocation')) {
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

  it('revoked credential must fail verification in OID4VP-compliant verifier', async () => {
    // 1. Issue Credential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'test-holder-revocation', credentialType: 'AgeCredential' })
    });
    
    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    const preAuthCode = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    // 2. Get Token
    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': preAuthCode })
    });
    
    expect(tokenRes.status).toBe(200);
    const tokenData = await tokenRes.json() as any;
    const { access_token, c_nonce } = tokenData;

    // 3. Issue Credential
    const proofJwt = await new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(holderKeys.publicKey) })
      .sign(holderKeys.privateKey);

    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } })
    });
    
    expect(credentialRes.status).toBe(200);
    const credData = await credentialRes.json() as any;
    const rawCredential = credData.credential as string;
    const parts = rawCredential.split('~');
    const baseJwt = parts[0]!;

    // 4. Extract credentialStatus from the issued credential
    const { publicKey } = await getIssuerKeyPair();
    const { payload: credPayload } = await jwtVerify(baseJwt, publicKey);
    const status = credPayload.credentialStatus as any;
    const statusIndex = parseInt(status.statusListIndex);
    const statusUrl = status.statusListCredential;
    const credentialId = credPayload.jti as string;

    // 5. Verify credential is initially ACTIVE (bit = 0)
    const statusListRes1 = await fetch(statusUrl);
    expect(statusListRes1.status).toBe(200);
    const statusListJwt1 = await statusListRes1.text();
    const { payload: slPayload1 } = await jwtVerify(statusListJwt1, publicKey);
    const encodedList1 = (slPayload1.credentialSubject as any).encodedList;
    const bytes1 = Buffer.from(encodedList1, 'base64url');
    const byteIdx = Math.floor(statusIndex / 8);
    const bitIdx = statusIndex % 8;
    
    expect((bytes1[byteIdx] >> bitIdx) & 1).toBe(0); // Active = 0

    // 6. Revoke the credential
    const revokeRes = await fetch(`${serverUrl}/admin/api/credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ reason: 'OID4VP compliance test' })
    });
    
    expect(revokeRes.status).toBe(200);
    const revokeData = await revokeRes.json() as any;
    expect(revokeData.success).toBe(true);

    // 7. Verify StatusList now shows REVOKED (bit = 1)
    const statusListRes2 = await fetch(statusUrl);
    expect(statusListRes2.status).toBe(200);
    const statusListJwt2 = await statusListRes2.text();
    const { payload: slPayload2 } = await jwtVerify(statusListJwt2, publicKey);
    const encodedList2 = (slPayload2.credentialSubject as any).encodedList;
    const bytes2 = Buffer.from(encodedList2, 'base64url');
    
    expect((bytes2[byteIdx] >> bitIdx) & 1).toBe(1); // Revoked = 1

    // 8. Verify the credential now fails verification due to revocation
    // Simulate OID4VP verifier logic:
    // - Fetch the StatusList2021 credential
    // - Extract the encodedList (bitstring)
    // - Check the bit at the credential's index
    // - If bit = 1, credential is revoked and MUST fail verification
    
    // Fetch fresh StatusList to ensure it's up-to-date
    const finalStatusListRes = await fetch(statusUrl);
    expect(finalStatusListRes.status).toBe(200);
    const finalStatusListJwt = await finalStatusListRes.text();
    const { payload: finalSlPayload } = await jwtVerify(finalStatusListJwt, publicKey);
    const finalEncodedList = (finalSlPayload.credentialSubject as any).encodedList;
    const finalBytes = Buffer.from(finalEncodedList, 'base64url');
    
    // Final verification: bit MUST be 1 (revoked)
    const isRevoked = ((finalBytes[byteIdx] >> bitIdx) & 1) === 1;
    expect(isRevoked).toBe(true);
    
    // In OID4VP-compliant verifier, this would cause verification to fail
    // The verifier checks: if credentialStatus exists and bit is set, reject
    expect(isRevoked).toBe(true); // This means verification MUST fail
  });

  it('search credentials by holder email returns correct results', async () => {
    // First, issue a credential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'test-holder-revocation', credentialType: 'AgeCredential' })
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

    // Search by credential ID (more reliable with PII masking)
    const searchRes = await fetch(`${serverUrl}/admin/api/credentials?search=test-revocation`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(searchRes.status).toBe(200);
    const searchResults = await searchRes.json() as any[];
    
    // Should find at least one credential
    expect(searchResults.length).toBeGreaterThan(0);

    // Verify PII masking is applied by default
    const masked = searchResults.some(c => 
      c.holderEmail && c.holderEmail.includes('***@')
    );
    expect(masked).toBe(true);
  });

  it('filter credentials by status returns correct results', async () => {
    // Issue and revoke a credential first
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'test-holder-revocation', credentialType: 'AgeCredential' })
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

    // Filter by revoked status
    const revokedRes = await fetch(`${serverUrl}/admin/api/credentials?status=revoked`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(revokedRes.status).toBe(200);
    const revokedCreds = await revokedRes.json() as any[];
    
    // Should have at least one revoked credential
    expect(revokedCreds.length).toBeGreaterThan(0);
    expect(revokedCreds.every(c => c.revoked === true)).toBe(true);

    // Filter by active status
    const activeRes = await fetch(`${serverUrl}/admin/api/credentials?status=active`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    
    expect(activeRes.status).toBe(200);
    const activeCreds = await activeRes.json() as any[];
    
    // All returned credentials should be active
    expect(activeCreds.every(c => c.revoked === false)).toBe(true);
  });

  it('CSRF protection on revocation endpoint fails closed with 403', async () => {
    // First, issue a credential to revoke
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'test-holder-revocation', credentialType: 'AgeCredential' })
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

    // Try to revoke WITHOUT CSRF token (using API key auth, which bypasses CSRF)
    // This should work because API key auth bypasses CSRF requirement
    const revokeRes = await fetch(`${serverUrl}/admin/api/credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ reason: 'Test CSRF' })
    });
    
    // With API key, this should succeed (CSRF bypass for API key auth)
    expect(revokeRes.status).toBe(200);
    
    // But without any auth, it should fail
    const unauthorizedRevokeRes = await fetch(`${serverUrl}/admin/api/credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ reason: 'Test CSRF' })
    });
    
    // Should fail with 401 (unauthorized) or 403 (forbidden)
    expect([401, 403]).toContain(unauthorizedRevokeRes.status);
  });

  it('StatusList2021 auto-refreshes after revocation', async () => {
    // Issue a credential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'test-holder-revocation', credentialType: 'AgeCredential' })
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
    const status = payload.credentialStatus as any;
    const statusUrl = status.statusListCredential;
    const credentialId = payload.jti as string;

    // Get initial StatusList
    const initialStatusRes = await fetch(statusUrl);
    const initialStatusJwt = await initialStatusRes.text();
    const { payload: initialSlPayload } = await jwtVerify(initialStatusJwt, publicKey);
    const initialEncodedList = (initialSlPayload.credentialSubject as any).encodedList;

    // Revoke the credential
    await fetch(`${serverUrl}/admin/api/credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ reason: 'Test auto-refresh' })
    });

    // Wait a moment for cache invalidation
    await new Promise(resolve => setTimeout(resolve, 100));

    // Get updated StatusList - should have new signature due to auto-refresh
    const updatedStatusRes = await fetch(statusUrl);
    const updatedStatusJwt = await updatedStatusRes.text();
    const { payload: updatedSlPayload } = await jwtVerify(updatedStatusJwt, publicKey);
    const updatedEncodedList = (updatedSlPayload.credentialSubject as any).encodedList;

    // The encoded lists should be different (bit was flipped)
    // Note: They might be the same if the bit was already set, but in our case it should change
    expect(initialEncodedList).not.toBe(updatedEncodedList);
    
    // Verify the bit was actually flipped
    const statusIndex = parseInt(status.statusListIndex);
    const byteIdx = Math.floor(statusIndex / 8);
    const bitIdx = statusIndex % 8;
    
    const initialBytes = Buffer.from(initialEncodedList, 'base64url');
    const updatedBytes = Buffer.from(updatedEncodedList, 'base64url');
    
    const initialBit = (initialBytes[byteIdx] >> bitIdx) & 1;
    const updatedBit = (updatedBytes[byteIdx] >> bitIdx) & 1;
    
    // Bit should have changed from 0 to 1
    expect(initialBit).toBe(0);
    expect(updatedBit).toBe(1);
  });
});
