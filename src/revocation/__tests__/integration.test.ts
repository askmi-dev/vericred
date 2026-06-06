import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, calculateJwkThumbprint } from 'jose';
import { mkdirSync, existsSync, writeFileSync, rmSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';
import { getIssuerKeyPair } from '../../keys/manager.js';

describe('Revocation Integration Flow', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  let holderKeys: { privateKey: import('jose').KeyLike; publicKey: import('jose').KeyLike };
  let holderThumbprint: string;

  beforeAll(async () => {
    const tempDir = './src/revocation/__tests__/temp-data-integration';
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
    mkdirSync(tempDir, { recursive: true });

    const mockHolders = [
      { id: 'rev-holder-01', email: 'rev-holder@example.com', firstName: 'Rev', lastName: 'Holder', dateOfBirth: '1990-01-01' }
    ];
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify(mockHolders, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['ISSUER_URL'] = 'http://localhost:3515';
    process.env['PORT'] = '3515';
    serverUrl = 'http://localhost:3515';

    holderKeys = await generateKeyPair('ES256');
    const publicJwk = await exportJWK(holderKeys.publicKey);
    holderThumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');

    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('handles the full lifecycle: Issue -> Verify -> Revoke -> Verify Failure', async () => {
    // 1. Issue Credential
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'rev-holder-01', credentialType: 'AgeCredential' })
    });
    const offerData = await offerRes.json() as any;
    if (offerRes.status !== 200) {
      console.error('Offer generation failed:', offerData);
    }
    expect(offerRes.status).toBe(200);
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
    const statusIndex = parseInt(status.statusListIndex);
    const statusUrl = status.statusListCredential;

    // 2. Verify Initial Status (Active)
    const statusListRes = await fetch(statusUrl);
    expect(statusListRes.status).toBe(200);
    const statusListJwt = await statusListRes.text();
    const { payload: slPayload } = await jwtVerify(statusListJwt, publicKey);
    const encodedList = (slPayload.credentialSubject as any).encodedList;
    const bytes = Buffer.from(encodedList, 'base64url');
    
    // Check if bit at statusIndex is 0 (Active)
    const byteIdx = Math.floor(statusIndex / 8);
    const bitIdx = statusIndex % 8;
    expect((bytes[byteIdx] >> bitIdx) & 1).toBe(0);

    // 3. Revoke Credential via Admin API
    const revokeRes = await fetch(`${serverUrl}/admin/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ credentialId: payload.jti, reason: 'Testing revocation flow' })
    });
    expect(revokeRes.status).toBe(200);
    const revokeData = await revokeRes.json() as any;
    expect(revokeData.success).toBe(true);

    // 4. Verify Final Status (Revoked)
    // We need to fetch the status list again
    const statusListRes2 = await fetch(statusUrl);
    expect(statusListRes2.status).toBe(200);
    const statusListJwt2 = await statusListRes2.text();
    const { payload: slPayload2 } = await jwtVerify(statusListJwt2, publicKey);
    const encodedList2 = (slPayload2.credentialSubject as any).encodedList;
    const bytes2 = Buffer.from(encodedList2, 'base64url');
    
    // Check if bit at statusIndex is 1 (Revoked)
    expect((bytes2[byteIdx] >> bitIdx) & 1).toBe(1);

    // 5. Attempt to revoke again (should fail)
    const revokeRes2 = await fetch(`${serverUrl}/admin/revoke`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ credentialId: payload.jti })
    });
    expect(revokeRes2.status).toBe(200);
    const revokeData2 = await revokeRes2.json() as any;
    expect(revokeData2.success).toBe(false);
  });
});
