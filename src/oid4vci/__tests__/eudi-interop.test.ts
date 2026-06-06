import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, calculateJwkThumbprint, importJWK } from 'jose';
import { createHash } from 'crypto';
import { mkdirSync, existsSync, writeFileSync, rmSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';
import { getIssuerKeyPair } from '../../keys/manager.js';
import { decodeDisclosure } from '../../sdjwt/disclosures.js';

describe('EUDI-Wallet Interoperability and Cryptographic Presentation Test', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  let holderKeys: { privateKey: import('jose').KeyLike; publicKey: import('jose').KeyLike };
  let holderThumbprint: string;

  beforeAll(async () => {
    const tempDir = './src/oid4vci/__tests__/temp-data-interop';
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
    mkdirSync(tempDir, { recursive: true });

    // Write a specific mock holders database containing a holder with valid dateOfBirth
    // Born in 2007, making them 19 in 2026 (age_over_18 = true, age_over_21 = false)
    const mockHolders = [
      {
        id: 'eudi-holder-01',
        email: 'eudi-holder@example.com',
        dateOfBirth: '2007-05-05',
        firstName: 'EUDI',
        lastName: 'Wallet'
      }
    ];
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify(mockHolders, null, 2));

    // Set isolated database directory, issuer URL and port to avoid conflicts
    process.env['DATA_DIR'] = tempDir;
    process.env['ISSUER_URL'] = 'http://localhost:3514';
    process.env['PORT'] = '3514';
    serverUrl = 'http://localhost:3514';

    // Generate fresh P-256 holder key pair
    holderKeys = await generateKeyPair('ES256');
    const publicJwk = await exportJWK(holderKeys.publicKey);
    holderThumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');

    // Import and spin up the server
    await import('../../server.js');

    // Wait for the Express server to start listening
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('performs full E2E issuance, deconstructs SD-JWT-VC, simulates selective presentation, and verifies presentation cryptographically', async () => {
    // ────────────────────────────────────────────────────────────────────────
    // STEP 1: Issue Credential Offer
    // ────────────────────────────────────────────────────────────────────────
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({
        holderId: 'eudi-holder-01',
        credentialType: 'AgeCredential'
      })
    });

    expect(offerRes.status).toBe(200);
    const offerData = await offerRes.json() as any;
    expect(offerData.offer.credential_configuration_ids).toEqual(['AgeCredential']);

    const preAuthGrant = offerData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
    const preAuthCode = preAuthGrant['pre-authorized_code'];
    expect(preAuthCode).toBeTruthy();

    // ────────────────────────────────────────────────────────────────────────
    // STEP 2: Exchange Pre-Authorized Code for Access Token and Nonce
    // ────────────────────────────────────────────────────────────────────────
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

    // ────────────────────────────────────────────────────────────────────────
    // STEP 3: Create Holder Proof of Possession JWT (Binding Proof)
    // ────────────────────────────────────────────────────────────────────────
    const publicJwk = await exportJWK(holderKeys.publicKey);
    const proofJwt = await new SignJWT({
      aud: serverUrl,
      iat: Math.floor(Date.now() / 1000),
      nonce: cNonce
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
      .sign(holderKeys.privateKey);

    // ────────────────────────────────────────────────────────────────────────
    // STEP 4: Request Issued SD-JWT-VC
    // ────────────────────────────────────────────────────────────────────────
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
    const rawCredentialString = credData.credential as string;
    expect(rawCredentialString).toBeTruthy();

    // ────────────────────────────────────────────────────────────────────────
    // STEP 5: Deconstruct SD-JWT-VC and Verify Issuer Signature & Disclosures
    // ────────────────────────────────────────────────────────────────────────
    const parts = rawCredentialString.split('~');
    const baseJwt = parts[0]!;
    const disclosures = parts.slice(1, -1); // discard JWT and the trailing empty element
    expect(baseJwt).toBeTruthy();
    expect(disclosures.length).toBeGreaterThan(0);

    // Get the Issuer's Public Key to verify the base JWT signature
    const { publicKey: issuerPublicKey } = await getIssuerKeyPair();
    const { payload: jwtPayload } = await jwtVerify(baseJwt, issuerPublicKey);

    expect(jwtPayload.vct).toBe('AgeCredential');
    expect(jwtPayload._sd_alg).toBe('sha-256');
    expect(jwtPayload.cnf).toEqual({ jkt: holderThumbprint });

    // Verify credentialStatus embedding (Phase 3 Task 13)
    expect(jwtPayload.credentialStatus).toBeDefined();
    const status = jwtPayload.credentialStatus as any;
    expect(status.type).toBe('StatusList2021Entry');
    expect(status.statusPurpose).toBe('revocation');
    expect(status.statusListIndex).toBe('0');
    expect(status.id).toContain('#0');
    expect(status.statusListCredential).toContain('/status/');

    const sdHashes = jwtPayload._sd as string[];
    expect(sdHashes).toBeInstanceOf(Array);
    expect(sdHashes.length).toBe(disclosures.length);

    // Audit and map all disclosures to verify they correspond to hashes listed in _sd
    const mappedClaims: Record<string, any> = {};
    const disclosureMap: Record<string, string> = {}; // claimName -> disclosureString

    for (const d of disclosures) {
      const [_salt, claimName, claimValue] = decodeDisclosure(d);
      mappedClaims[claimName] = claimValue;
      disclosureMap[claimName] = d;

      // Compute the SHA-256 hash of this disclosure to match _sd list
      const actualDigest = createHash('sha256').update(d).digest('base64url');
      expect(sdHashes).toContain(actualDigest);
    }

    // Verify template claims inside AgeCredential are correct
    expect(mappedClaims.age_over_18).toBe(true);
    expect(mappedClaims.age_over_21).toBe(false);
    expect(mappedClaims.age_attested_at).toBeTruthy();

    // ────────────────────────────────────────────────────────────────────────
    // STEP 6: Simulate Selective Disclosure Presentation
    // ────────────────────────────────────────────────────────────────────────
    // The wallet is configured to ONLY present 'age_over_18' and HIDE 'age_over_21' & 'age_attested_at'
    const selectedClaims = ['age_over_18'];
    const presentedDisclosures = selectedClaims.map(name => disclosureMap[name]!).filter(Boolean);
    expect(presentedDisclosures.length).toBe(1);

    // Create Holder Key Binding Proof (KB-JWT) for the verifier
    const verifierNonce = 'verifier-transient-nonce-xyz-987';
    const verifierAudience = 'https://verifier.example.org';

    const kbJwt = await new SignJWT({
      aud: verifierAudience,
      nonce: verifierNonce,
      iat: Math.floor(Date.now() / 1000)
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
      .sign(holderKeys.privateKey);

    // Assemble the complete compact presentation string: <JWT>~<disclosure1>~...~<disclosureN>~~<holder_kb_jwt>
    const presentationString = `${baseJwt}~${presentedDisclosures.join('~')}~~${kbJwt}`;

    // ────────────────────────────────────────────────────────────────────────
    // STEP 7: Verify Presentation as Third-Party Verifier
    // ────────────────────────────────────────────────────────────────────────
    const verifierParts = presentationString.split('~');
    const verifierBaseJwt = verifierParts[0]!;
    const verifierDisclosures = verifierParts.slice(1, -2); // Exclude Base JWT, trailing empty, and KB-JWT
    const verifierKbJwt = verifierParts[verifierParts.length - 1]!;

    expect(verifierBaseJwt).toBe(baseJwt);
    expect(verifierKbJwt).toBe(kbJwt);
    expect(verifierDisclosures).toEqual(presentedDisclosures);

    // A. Verify the Issuer's signature over the base JWT
    const { payload: verifiedIssuerPayload } = await jwtVerify(verifierBaseJwt, issuerPublicKey);
    expect(verifiedIssuerPayload.vct).toBe('AgeCredential');

    // B. Verify Holder Key Binding (KB-JWT) using the holder's public key
    const holderCnf = verifiedIssuerPayload.cnf as { jkt: string };
    expect(holderCnf).toBeDefined();
    expect(holderCnf.jkt).toBe(holderThumbprint);

    // Import the holder public key from the raw key context to verify KB-JWT
    const { payload: verifiedKbPayload } = await jwtVerify(verifierKbJwt, holderKeys.publicKey);
    expect(verifiedKbPayload.aud).toBe(verifierAudience);
    expect(verifiedKbPayload.nonce).toBe(verifierNonce);

    // C. Decode and verify only the disclosed claims
    const verifiedClaims: Record<string, any> = {};
    const baseSdList = verifiedIssuerPayload._sd as string[];

    for (const d of verifierDisclosures) {
      const [_salt, name, value] = decodeDisclosure(d);
      verifiedClaims[name] = value;

      // Re-hash and check presence in original _sd list
      const actualDigest = createHash('sha256').update(d).digest('base64url');
      expect(baseSdList).toContain(actualDigest);
    }

    // Assert that 'age_over_18' is verified as true
    expect(verifiedClaims.age_over_18).toBe(true);

    // D. Assert privacy guarantees: hidden claims are completely missing and unguessable
    expect(verifiedClaims.age_over_21).toBeUndefined();
    expect(verifiedClaims.age_attested_at).toBeUndefined();

    // Verify that an attacker cannot deduce hidden claims without the disclosures
    const age21Disclosure = disclosureMap['age_over_21']!;
    const age21Hash = createHash('sha256').update(age21Disclosure).digest('base64url');
    expect(baseSdList).toContain(age21Hash);

    // Verify that an attacker trying to guess has no salt to reconstruct the disclosure
    const fakeDisclosure = JSON.stringify(['no-salt', 'age_over_21', false]);
    const fakeEncoded = Buffer.from(fakeDisclosure).toString('base64url');
    const fakeHash = createHash('sha256').update(fakeEncoded).digest('base64url');
    expect(baseSdList).not.toContain(fakeHash);
  });
});
