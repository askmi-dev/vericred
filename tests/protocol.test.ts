import { beforeAll, afterAll, describe, it, expect, vi, afterEach } from 'vitest';
import express from 'express';
import type { Server } from 'node:http';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createTokenRouter, issuePreAuthCode } from '../src/oid4vci/token.js';
import { createCredentialRouter, resolveMappedData } from '../src/oid4vci/issuer.js';
import { createMetadataRouter } from '../src/oid4vci/metadata.js';
import { createOid4vpRouter } from '../src/oid4vp/router.js';
import { getIssuerKeyPair } from '../src/keys/manager.js';
import { loadConfig } from '../src/config/loader.js';
import { getTemplate } from '../src/credentials/registry.js';

describe('Final protocol and privacy boundaries', () => {
  let server: Server, url: string;
  const post = (path: string, body: unknown, token?: string) => fetch(url + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
    body: JSON.stringify(body),
  });
  beforeAll(async () => {
    await getIssuerKeyPair();
    const app = express();
    app.use(express.json(), express.urlencoded({ extended: false }));
    app.use(createMetadataRouter(), createTokenRouter(), createCredentialRouter('test-secret'), createOid4vpRouter());
    server = await new Promise<Server>(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('No TCP address');
    url = 'http://127.0.0.1:' + address.port;
  });
  afterAll(() => new Promise<void>((resolve, reject) => server.close(e => e ? reject(e) : resolve())));
  afterEach(() => vi.restoreAllMocks());
  async function grant() {
    const response = await post('/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': issuePreAuthCode({ id: 'holder', dateOfBirth: '1990-01-01' }, 'AgeCredential'),
    });
    expect(response.status).toBe(200);
    return (await response.json() as any).access_token as string;
  }
  async function proof(nonce: string) {
    const keys = await generateKeyPair('ES256');
    return new SignJWT({ nonce }).setAudience(loadConfig().issuer.url).setIssuedAt()
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(keys.publicKey) }).sign(keys.privateKey);
  }
  const request = (jwt: string) => ({ credential_configuration_id: 'AgeCredential', proofs: { jwt: [jwt] } });
  it('discovers nonce, OAuth grant, VCT and emitted age claims without advertising DOB', async () => {
    const metadata = await (await fetch(url + '/.well-known/openid-credential-issuer')).json() as any;
    expect(metadata.nonce_endpoint).toBe(loadConfig().issuer.url + '/nonce');
    expect(Object.keys(metadata.credential_configurations_supported)).toEqual(['AgeCredential']);
    const age = metadata.credential_configurations_supported.AgeCredential;
    expect(age.vct).toBe('urn:vericred:credential:AgeCredential:1');
    expect(age.credential_metadata.claims.map((c: any) => c.path[0])).toContain('age_over_18');
    expect(JSON.stringify(age)).not.toContain('dateOfBirth');
    const auth = await (await fetch(url + '/.well-known/oauth-authorization-server')).json() as any;
    expect(auth.grant_types_supported).toEqual(['urn:ietf:params:oauth:grant-type:pre-authorized_code']);
    const jwks = await (await fetch(url + '/.well-known/jwks.json')).json() as any;
    expect(jwks.keys.length).toBeGreaterThan(0);
    expect(jwks.keys.every((k: any) => !k.d && k.alg === 'ES256')).toBe(true);
  });
  it('consumes a public nonce once across concurrent requests using different access tokens', async () => {
    const tokens = await Promise.all([grant(), grant()]);
    const nonceResponse = await post('/nonce', {});
    expect(nonceResponse.headers.get('cache-control')).toBe('no-store');
    const nonce = (await nonceResponse.json() as any).c_nonce;
    const body = request(await proof(nonce));
    const responses = await Promise.all(tokens.map(token => post('/credentials', body, token)));
    expect(responses.map(r => r.status).sort()).toEqual([200, 400]);
    const successful = await responses.find(r => r.status === 200)!.json() as any;
    expect(successful.credentials).toHaveLength(1);
    expect(successful.credential).toBeUndefined();
  });
  it('rejects expired and unknown public nonces', async () => {
    const token = await grant();
    const nonce = (await (await post('/nonce', {})).json() as any).c_nonce;
    const signed = await proof(nonce);
    const now = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(now + 301_000);
    // Mint a new token at the later time so only the nonce is expired.
    const freshToken = await grant();
    expect((await post('/credentials', request(signed), freshToken)).status).toBe(400);
    vi.restoreAllMocks();
    expect((await post('/credentials', request(await proof('unknown')), await grant())).status).toBe(400);
  });
  it('rejects another configuration, mixed proof shapes, and unsupported batch requests', async () => {
    const token = await grant();
    const nonce = (await (await post('/nonce', {})).json() as any).c_nonce;
    const jwt = await proof(nonce);
    expect((await post('/credentials', { ...request(jwt), credential_configuration_id: 'EmployeeCredential' }, token)).status).toBe(400);
    expect((await post('/credentials', { ...request(jwt), proof: { proof_type: 'jwt', jwt } }, token)).status).toBe(400);
    expect((await post('/credentials', { ...request(jwt), proofs: { jwt: [jwt, jwt] } }, token)).status).toBe(400);
    expect((await post('/credentials', request(jwt), token)).status).toBe(200);
  });
  it('requires DCQL state and keyed response shape without implicit downgrade', async () => {
    const session = await (await post('/api/oid4vp/initiate', { credentialType: 'AgeCredential' })).json() as any;
    expect(session.protocol).toBe('openid4vp-1.0');
    const path = '/api/oid4vp/response/' + session.sessionId;
    expect((await post(path, { vp_token: 'raw-legacy-presentation' })).status).toBe(401);
    expect((await post(path, { state: session.sessionId, vp_token: { wrong: ['anything'] } })).status).toBe(401);
    expect((await post('/api/oid4vp/initiate', { protocol: 'unknown' })).status).toBe(400);
  });
  it('requires explicit mappings and never guesses optional fields or alternative source names', () => {
    const template = getTemplate('EmployeeCredential');
    const holder = { given_name: 'Wrong', chosen: 'Right', family_name: 'Family', organization: 'Org', role: 'Role', department: 'Private' };
    const mappings = { given_name: 'chosen', family_name: 'family_name', organization: 'organization', role: 'role' };
    const mapped = resolveMappedData(template, mappings, holder);
    expect(mapped.errors).toEqual([]);
    expect(mapped.mappedData.given_name).toBe('Right');
    expect(mapped.mappedData.department).toBeUndefined();
    expect(resolveMappedData(template, { ...mappings, given_name: 'missing' }, holder).errors).toHaveLength(1);
    expect(resolveMappedData(template, { ...mappings, department: 'department' }, holder).mappedData.department).toBe('Private');
  });
});
