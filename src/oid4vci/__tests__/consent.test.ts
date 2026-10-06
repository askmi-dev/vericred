import { describe, it, expect, beforeAll, vi } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, decodeJwt } from 'jose';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';
import { registerTemplate } from '../../credentials/registry.js';
import { decodeDisclosure } from '../../sdjwt/disclosures.js';

// A dedicated, test-only template with requiresConsent: true. We deliberately
// do NOT flip this on any of the shipped templates (Age/Employee/Membership)
// -- they're used as the "simple default" fixture across many other test
// files (revocation, EUDI-interop, admin) that expect today's immediate-
// issuance behavior. Registering a separate template here proves the
// opt-in-per-template contract without touching any of that.
registerTemplate({
  id: 'ConsentTestCredential',
  displayName: 'Consent Test Credential',
  requiredFields: ['givenName'],
  optionalFields: [],
  requiresConsent: true,
  buildClaims(holderData) {
    return { test_claim: holderData['givenName'] };
  },
  validateMappings() {
    return [];
  },
});

// buildClaims here returns a different value every call (an incrementing
// counter), so a test can tell whether /credentials issued the exact
// snapshot reviewed at consent time or recomputed claims live.
let snapshotCallCount = 0;
registerTemplate({
  id: 'ConsentSnapshotTestCredential',
  displayName: 'Consent Snapshot Test Credential',
  requiredFields: [],
  optionalFields: [],
  requiresConsent: true,
  buildClaims() {
    snapshotCallCount += 1;
    return { stamp: snapshotCallCount };
  },
  validateMappings() {
    return [];
  },
});

describe('Pre-issuance consent gate', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  let holderKeys: { privateKey: import('jose').KeyLike; publicKey: import('jose').KeyLike };

  beforeAll(async () => {
    const tempDir = './src/oid4vci/__tests__/temp-data-consent';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });

    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
      {
        id: 'consent-holder-01',
        givenName: 'Alex',
        dateOfBirth: '1990-01-01',
        organization: 'ACME Guild',
        membershipType: 'supporter',
      },
    ], null, 2));

    writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify({
      issuer: {
        name: 'VeriCred Test Issuer',
        url: 'http://localhost:3521',
        did: 'did:web:localhost%3A3521',
      },
      credential: { type: 'AgeCredential', expiresInDays: 30 },
      templateOptions: { ageThresholds: [18, 21] },
      dataSource: { type: 'json', path: `${tempDir}/holders.json` },
      fieldMappings: { dateOfBirth: 'dateOfBirth' },
    }, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = '3521';
    process.env['ISSUER_URL'] = 'http://localhost:3521';
    serverUrl = 'http://localhost:3521';

    holderKeys = await generateKeyPair('ES256');

    await import('../../server.js');
    await new Promise((resolve) => setTimeout(resolve, 500));
  });

  async function createOffer(credentialType: string) {
    const res = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'consent-holder-01', credentialType }),
    });
    return { res, data: (await res.json()) as any };
  }

  it('returns consent_url, not offer_uri, for a requiresConsent template', async () => {
    const { res, data } = await createOffer('ConsentTestCredential');
    expect(res.status).toBe(200);
    expect(data.consent_required).toBe(true);
    expect(data.consent_url).toContain('/consent/');
    expect(data.offer).toBeUndefined();
    expect(data.offer_uri).toBeUndefined();
  });

  it('does not leak a pre-auth secret in the /offer response for a consent-gated template', async () => {
    const { data } = await createOffer('ConsentTestCredential');
    // The consent_url is the only thing a QR code (e.g. monitor.astro) would
    // ever encode for this template -- confirm there's nothing resembling a
    // redeemable pre-auth code anywhere in the response.
    const serialized = JSON.stringify(data);
    expect(serialized).not.toContain('pre-authorized_code');
    expect(serialized).not.toContain('openid-credential-offer://');
  });

  it('two offers for the same holder produce distinct consent URLs', async () => {
    const first = await createOffer('ConsentTestCredential');
    const second = await createOffer('ConsentTestCredential');
    expect(first.data.consent_url).not.toBe(second.data.consent_url);
  });

  it('non-consent templates (AgeCredential) are completely unaffected', async () => {
    const { res, data } = await createOffer('AgeCredential');
    expect(res.status).toBe(200);
    expect(data.consent_required).toBeUndefined();
    expect(data.offer.credential_configuration_ids).toEqual(['AgeCredential']);
    expect(data.offer_uri).toContain('openid-credential-offer://');
  });

  it('MembershipCredential (the first real template on the gate) shows correctly labeled claims and redeems end to end', async () => {
    const { res, data } = await createOffer('MembershipCredential');
    expect(res.status).toBe(200);
    expect(data.consent_required).toBe(true);
    const consentId = data.consent_url.split('/').pop();

    const claimsRes = await fetch(`${serverUrl}/consent/${consentId}/claims`);
    const claimsData = (await claimsRes.json()) as any;
    // Labels must key off the template's actual *output* claim names
    // (membership_type, snake_case) -- not its input field name
    // (membershipType) -- or they silently fall back to the raw key.
    expect(claimsData.claims).toEqual(
      expect.arrayContaining([
        { key: 'organization', label: 'Your organization', value: 'ACME Guild', required: true },
        { key: 'membership_type', label: 'Your membership type', value: 'supporter', required: true },
      ])
    );

    const decideRes = await fetch(`${serverUrl}/consent/${consentId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved: true }),
    });
    expect(decideRes.status).toBe(200);
    const decideData = (await decideRes.json()) as any;
    const preAuthCode =
      decideData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthCode,
      }),
    });
    const tokenData = (await tokenRes.json()) as any;

    const publicJwk = await exportJWK(holderKeys.publicKey);
    const proofJwt = await new SignJWT({
      aud: serverUrl,
      iat: Math.floor(Date.now() / 1000),
      nonce: tokenData.c_nonce,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
      .sign(holderKeys.privateKey);

    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenData.access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } }),
    });
    expect(credentialRes.status).toBe(200);
    const credData = (await credentialRes.json()) as any;
    const claims = decodeJwt(credData.credential.split('~')[0]) as any;
    expect(claims.vct).toBe('MembershipCredential');
  });

  it('GET /consent/:id/claims returns human-readable claim labels, never the raw pre-auth secret', async () => {
    const { data } = await createOffer('ConsentTestCredential');
    const consentId = data.consent_url.split('/').pop();

    const claimsRes = await fetch(`${serverUrl}/consent/${consentId}/claims`);
    expect(claimsRes.status).toBe(200);
    const claimsData = (await claimsRes.json()) as any;

    expect(claimsData.credentialType).toBe('ConsentTestCredential');
    expect(claimsData.claims).toEqual([{ key: 'test_claim', label: 'test_claim', value: 'Alex', required: true }]);
    // The claim shown is the actual output claim (test_claim = holder's given name),
    // never a raw secret or pre-auth code.
    expect(JSON.stringify(claimsData)).not.toContain('pre-authorized_code');
  });

  it('approving issues a genuinely redeemable offer (full /token + /credentials flow)', async () => {
    const { data } = await createOffer('ConsentTestCredential');
    const consentId = data.consent_url.split('/').pop();

    const decideRes = await fetch(`${serverUrl}/consent/${consentId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved: true }),
    });
    expect(decideRes.status).toBe(200);
    const decideData = (await decideRes.json()) as any;
    expect(decideData.offer_uri).toContain('openid-credential-offer://');

    const preAuthCode =
      decideData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
    expect(preAuthCode).toBeTruthy();

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthCode,
      }),
    });
    expect(tokenRes.status).toBe(200);
    const tokenData = (await tokenRes.json()) as any;

    const publicJwk = await exportJWK(holderKeys.publicKey);
    const proofJwt = await new SignJWT({
      aud: serverUrl,
      iat: Math.floor(Date.now() / 1000),
      nonce: tokenData.c_nonce,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
      .sign(holderKeys.privateKey);

    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenData.access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } }),
    });
    expect(credentialRes.status).toBe(200);
    const credData = (await credentialRes.json()) as any;

    const claims = decodeJwt(credData.credential.split('~')[0]) as any;
    expect(claims.vct).toBe('ConsentTestCredential');
  });

  it('issues exactly the claim values reviewed at consent time, never recomputed at /credentials', async () => {
    const { data } = await createOffer('ConsentSnapshotTestCredential');
    const consentId = data.consent_url.split('/').pop();

    const claimsRes = await fetch(`${serverUrl}/consent/${consentId}/claims`);
    const claimsData = (await claimsRes.json()) as any;
    const reviewedStamp = claimsData.claims.find((c: any) => c.key === 'stamp').value;

    const decideRes = await fetch(`${serverUrl}/consent/${consentId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved: true }),
    });
    const decideData = (await decideRes.json()) as any;
    const preAuthCode =
      decideData.offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

    const tokenRes = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': preAuthCode,
      }),
    });
    const tokenData = (await tokenRes.json()) as any;

    const publicJwk = await exportJWK(holderKeys.publicKey);
    const proofJwt = await new SignJWT({
      aud: serverUrl,
      iat: Math.floor(Date.now() / 1000),
      nonce: tokenData.c_nonce,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
      .sign(holderKeys.privateKey);

    const credentialRes = await fetch(`${serverUrl}/credentials`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenData.access_token}` },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proofJwt } }),
    });
    const credData = (await credentialRes.json()) as any;

    const disclosures = credData.credential.split('~').slice(1, -1);
    const issuedClaims: Record<string, unknown> = {};
    for (const d of disclosures) {
      const [, name, value] = decodeDisclosure(d);
      issuedClaims[name] = value;
    }

    // buildClaims() increments its counter on every call. If /credentials
    // recomputed live instead of reusing the snapshot, the issued stamp
    // would be one higher than what was reviewed and approved.
    expect(issuedClaims.stamp).toBe(reviewedStamp);
  });

  it('declining permanently kills the offer -- no further GET/POST succeeds', async () => {
    const { data } = await createOffer('ConsentTestCredential');
    const consentId = data.consent_url.split('/').pop();

    const decideRes = await fetch(`${serverUrl}/consent/${consentId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved: false }),
    });
    expect(decideRes.status).toBe(200);
    expect((await decideRes.json()) as any).toEqual({ declined: true });

    const claimsRes = await fetch(`${serverUrl}/consent/${consentId}/claims`);
    expect(claimsRes.status).toBe(404);

    const secondDecideRes = await fetch(`${serverUrl}/consent/${consentId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved: true }),
    });
    expect(secondDecideRes.status).toBe(410);
  });

  it('fails closed on an unknown consent id', async () => {
    const claimsRes = await fetch(`${serverUrl}/consent/does-not-exist/claims`);
    expect(claimsRes.status).toBe(404);

    const decideRes = await fetch(`${serverUrl}/consent/does-not-exist/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved: true }),
    });
    expect(decideRes.status).toBe(404);
  });

  it('fails closed once the 24h consent window has expired, never resurrects it', async () => {
    const { data } = await createOffer('ConsentTestCredential');
    const consentId = data.consent_url.split('/').pop();

    // Spy on Date.now only (not vi.useFakeTimers) -- a real fetch() to the
    // real listening server relies on real timers internally for its own
    // I/O; faking those out would hang the request. Date.now is all
    // consent.ts's expiry check reads, so this is sufficient and surgical.
    const realNow = Date.now;
    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => realNow() + 25 * 60 * 60 * 1000);
    try {
      const claimsRes = await fetch(`${serverUrl}/consent/${consentId}/claims`);
      expect(claimsRes.status).toBe(404);

      const decideRes = await fetch(`${serverUrl}/consent/${consentId}/decide`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved: true }),
      });
      expect(decideRes.status).toBe(404);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it('rejects a malformed decide body', async () => {
    const { data } = await createOffer('ConsentTestCredential');
    const consentId = data.consent_url.split('/').pop();

    const res = await fetch(`${serverUrl}/consent/${consentId}/decide`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approved: 'yes' }),
    });
    expect(res.status).toBe(400);
  });
});
