/**
 * Unlinkability by default (OID4VCI 1.0 batch issuance + IETF Token Status List).
 *
 * Requirement: copies of one credential issued in a batch must share no value
 * a verifier could use to link two presentations, apart from what every
 * credential of that type and day carries anyway (issuer, type, day-rounded
 * timestamps, status list URI, digest algorithm).
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, decodeProtectedHeader } from 'jose';
import { mkdirSync, existsSync, writeFileSync, rmSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';
import { getIssuerKeyPair } from '../../keys/manager.js';
import { statusAt } from '../../revocation/__tests__/token-status-helpers.js';

const PORT = 3523;
const serverUrl = `http://localhost:${PORT}`;
const adminApiKey = loadSecrets().adminApiKey;

/** Values every copy of a credential type legitimately has in common. */
const SHAREABLE_KEYS = new Set(['iss', 'vct', 'iat', 'exp', '_sd_alg', 'uri']);

async function newProof(cNonce: string) {
  const keys = await generateKeyPair('ES256');
  return new SignJWT({ aud: serverUrl, iat: Math.floor(Date.now() / 1000), nonce: cNonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(keys.publicKey) })
    .sign(keys.privateKey);
}

async function getToken(): Promise<{ accessToken: string; cNonce: string }> {
  const offerRes = await fetch(`${serverUrl}/offer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
    body: JSON.stringify({ holderId: 'batch-holder-01', credentialType: 'AgeCredential' }),
  });
  expect(offerRes.status).toBe(200);
  const offer = (await offerRes.json() as any).offer;
  const code = offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
  const tokenRes = await fetch(`${serverUrl}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }),
  });
  expect(tokenRes.status).toBe(200);
  const t = await tokenRes.json() as any;
  return { accessToken: t.access_token, cNonce: t.c_nonce };
}

function requestCredential(accessToken: string, body: unknown) {
  return fetch(`${serverUrl}/credentials`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
    body: JSON.stringify(body),
  });
}

/** Flatten every scalar in a JSON value into "key=value" strings. */
function leafValues(value: unknown, key = ''): string[] {
  if (Array.isArray(value)) return value.flatMap(v => leafValues(v, key));
  if (value && typeof value === 'object') {
    return Object.entries(value).flatMap(([k, v]) => leafValues(v, k));
  }
  return SHAREABLE_KEYS.has(key) ? [] : [`${key}=${String(value)}`];
}

async function issueBatch(n: number): Promise<string[]> {
  const { accessToken, cNonce } = await getToken();
  const proofs = await Promise.all(Array.from({ length: n }, () => newProof(cNonce)));
  const res = await requestCredential(accessToken, {
    credential_configuration_id: 'AgeCredential',
    proofs: { jwt: proofs },
  });
  expect(res.status).toBe(200);
  const body = await res.json() as any;
  expect(body.credentials).toHaveLength(n);
  return body.credentials.map((c: { credential: string }) => c.credential);
}

describe('Unlinkable batch issuance', () => {
  beforeAll(async () => {
    const tempDir = './src/oid4vci/__tests__/temp-data-batch';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
      { id: 'batch-holder-01', email: 'batch-holder@example.com', dateOfBirth: '2000-01-01' },
    ]));
    process.env['DATA_DIR'] = tempDir;
    process.env['ISSUER_URL'] = serverUrl;
    process.env['PORT'] = String(PORT);
    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('advertises batch issuance and the dc+sd-jwt format in issuer metadata', async () => {
    const meta = await (await fetch(`${serverUrl}/.well-known/openid-credential-issuer`)).json() as any;
    expect(meta.batch_credential_issuance.batch_size).toBeGreaterThanOrEqual(2);
    expect(meta.credential_configurations_supported.AgeCredential.format).toBe('dc+sd-jwt');
  });

  it('issues one dc+sd-jwt copy per proof, with no linkable value shared between copies', async () => {
    const credentials = await issueBatch(3);
    const { publicKey } = await getIssuerKeyPair();

    const perCopy: Set<string>[] = [];
    const iats = new Set<number>();
    for (const credential of credentials) {
      const [jwt, ...disclosures] = credential.split('~').filter(Boolean);
      expect(decodeProtectedHeader(jwt!).typ).toBe('dc+sd-jwt');
      const { payload } = await jwtVerify(jwt!, publicKey);

      // IETF Token Status List reference, not W3C StatusList2021
      expect(payload['credentialStatus']).toBeUndefined();
      const ref = (payload['status'] as any)?.status_list;
      expect(Number.isInteger(ref.idx)).toBe(true);
      expect(ref.uri.startsWith(`${serverUrl}/status/`)).toBe(true);

      // Timestamps rounded to the UTC day, so issuance time can't link copies
      expect((payload.iat as number) % 86400).toBe(0);
      iats.add(payload.iat as number);

      perCopy.push(new Set([...leafValues(payload), ...disclosures.map(d => `disclosure=${d}`)]));
    }

    expect(iats.size).toBe(1);
    for (let i = 0; i < perCopy.length; i++) {
      for (let j = i + 1; j < perCopy.length; j++) {
        const shared = [...perCopy[i]!].filter(v => perCopy[j]!.has(v));
        expect(shared).toEqual([]);
      }
    }
  });

  it('rejects a batch that reuses one holder key (copies would be linkable via cnf)', async () => {
    const { accessToken, cNonce } = await getToken();
    const proof = await newProof(cNonce);
    const res = await requestCredential(accessToken, { proofs: { jwt: [proof, proof] } });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error).toBe('invalid_proof');
  });

  it('rejects a batch larger than the advertised batch_size', async () => {
    const meta = await (await fetch(`${serverUrl}/.well-known/openid-credential-issuer`)).json() as any;
    const { accessToken, cNonce } = await getToken();
    const proofs = await Promise.all(
      Array.from({ length: meta.batch_credential_issuance.batch_size + 1 }, () => newProof(cNonce)),
    );
    const res = await requestCredential(accessToken, { proofs: { jwt: proofs } });
    expect(res.status).toBe(400);
    expect((await res.json() as any).error).toBe('invalid_credential_request');
  });

  it('publishes a Token Status List, and revoking one copy revokes the whole batch', async () => {
    const credentials = await issueBatch(2);
    const { publicKey } = await getIssuerKeyPair();
    const payloads = await Promise.all(credentials.map(async c => (await jwtVerify(c.split('~')[0]!, publicKey)).payload));
    const refs = payloads.map(p => (p['status'] as any).status_list as { idx: number; uri: string });

    const fetchList = async () => {
      const res = await fetch(refs[0]!.uri);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('application/statuslist+jwt');
      const jwt = await res.text();
      expect(decodeProtectedHeader(jwt).typ).toBe('statuslist+jwt');
      const { payload } = await jwtVerify(jwt, publicKey);
      expect(payload.sub).toBe(refs[0]!.uri);
      expect((payload['status_list'] as any).bits).toBe(1);
      return (payload['status_list'] as any).lst as string;
    };

    const before = await fetchList();
    for (const r of refs) expect(statusAt(before, r.idx)).toBe(0);

    const revokeRes = await fetch(`${serverUrl}/admin/revoke`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
      body: JSON.stringify({ credentialId: payloads[0]!.jti, reason: 'batch revocation test' }),
    });
    expect((await revokeRes.json() as any).success).toBe(true);

    const after = await fetchList();
    for (const r of refs) expect(statusAt(after, r.idx)).toBe(1);
  });
});
