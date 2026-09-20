import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import express from 'express';
import type { Server } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT, decodeJwt, type KeyLike, type JWTPayload } from 'jose';
import { createOid4vpRouter } from '../router.js';
import { verifyPresentation } from '../verify.js';
import { createCredentialRouter } from '../../oid4vci/issuer.js';
import { createTokenRouter, issuePreAuthCode } from '../../oid4vci/token.js';
import { getIssuerKeyPair } from '../../keys/manager.js';
import { loadConfig } from '../../config/loader.js';
import { revokeCredential, getIssuedCredentials } from '../../revocation/statuslist.js';

type Session = { sessionId: string; nonce: string; readToken: string; requestUri: string; qrCodeDataUrl: string };
type Credential = { issuerJwt: string; disclosures: string[]; privateKey: KeyLike };
const hash = (value: string) => createHash('sha256').update(value, 'ascii').digest('base64url');
const disclosure = (name: string, value: unknown, salt = 'independent-test-salt') =>
  Buffer.from(JSON.stringify([salt, name, value])).toString('base64url');

describe('OID4VP: actual issuance, presentation integrity and session access', () => {
  let server: Server;
  let baseUrl: string;
  let credential: Credential;
  const post = (path: string, body: unknown = {}) => fetch(baseUrl + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  async function initiate(): Promise<Session> {
    const response = await post('/api/oid4vp/initiate', { credentialType: 'AgeCredential', protocol: 'legacy-draft' });
    expect(response.status).toBe(200);
    return response.json() as Promise<Session>;
  }
  const read = (session: Session, token = session.readToken) => fetch(baseUrl + '/api/oid4vp/session/' + session.sessionId, {
    headers: token ? { Authorization: 'Bearer ' + token } : {},
  });
  async function issue(dateOfBirth = '1990-01-01'): Promise<Credential> {
    const holderKeys = await generateKeyPair('ES256');
    const publicJwk = await exportJWK(holderKeys.publicKey);
    const tokenResponse = await post('/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': issuePreAuthCode({ id: 'test-holder', dateOfBirth }, 'AgeCredential'),
    });
    expect(tokenResponse.status).toBe(200);
    const token = await tokenResponse.json() as { access_token: string; c_nonce: string };
    const proof = await new SignJWT({ nonce: token.c_nonce })
      .setAudience(loadConfig().issuer.url).setIssuedAt()
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk }).sign(holderKeys.privateKey);
    const response = await fetch(baseUrl + '/credentials', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token.access_token },
      body: JSON.stringify({ format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proof } }),
    });
    expect(response.status).toBe(200);
    const body = await response.json() as { credential: string };
    const [issuerJwt, ...parts] = body.credential.split('~');
    expect(parts.pop()).toBe('');
    expect(decodeJwt(issuerJwt).cnf).toEqual({ jwk: publicJwk });
    return { issuerJwt, disclosures: parts, privateKey: holderKeys.privateKey };
  }
  function selected(source: Credential) {
    return source.disclosures.filter(d => JSON.parse(Buffer.from(d, 'base64url').toString())[1] === 'age_over_18');
  }
  async function presentation(session: Session, opts: {
    source?: Credential; disclosures?: string[]; issuerJwt?: string; kb?: JWTPayload;
    signingKey?: KeyLike; omitHash?: boolean;
  } = {}) {
    const source = opts.source ?? credential;
    const disclosures = opts.disclosures ?? selected(source);
    const sdJwt = [opts.issuerJwt ?? source.issuerJwt, ...disclosures, ''].join('~');
    const kb = await new SignJWT({
      nonce: session.nonce, aud: loadConfig().issuer.url + '/api/oid4vp/client-metadata',
      iat: Math.floor(Date.now() / 1000), ...(opts.omitHash ? {} : { sd_hash: hash(sdJwt) }), ...opts.kb,
    }).setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).sign(opts.signingKey ?? source.privateKey);
    return sdJwt + kb;
  }
  async function resign(payload: JWTPayload, typ = 'dc+sd-jwt') {
    const { privateKey, kid } = await getIssuerKeyPair();
    return new SignJWT(payload).setProtectedHeader({ alg: 'ES256', kid, typ }).sign(privateKey);
  }
  async function rejected(session: Session, token: unknown) {
    const response = await post('/api/oid4vp/response/' + session.sessionId, { vp_token: token });
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'invalid_presentation' });
    expect(await (await read(session)).json()).toEqual({ status: 'initiated', claims: null });
  }
  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));
    app.use(createTokenRouter());
    app.use(createCredentialRouter('test-pseudonym-secret'));
    app.use(createOid4vpRouter());
    server = await new Promise<Server>(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Expected TCP listener');
    baseUrl = 'http://127.0.0.1:' + address.port;
    credential = await issue();
  });
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllEnvs(); });
  afterAll(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));

  it('issues a holder-bound credential and verifies only the selected signed claim', async () => {
    const session = await initiate();
    const response = await post('/api/oid4vp/response/' + session.sessionId, { vp_token: await presentation(session) });
    expect(response.status).toBe(200);
    const result = await read(session);
    expect(result.headers.get('cache-control')).toBe('no-store');
    expect(await result.json()).toEqual({ status: 'verified', claims: { age_over_18: true } });
  });
  it.each([
    ['vc+sd-jwt', 'urn:vericred:credential:AgeCredential:1'],
    ['dc+sd-jwt', 'AgeCredential'],
    ['vc+sd-jwt', 'AgeCredential'],
  ])('restricts legacy typ=%s vct=%s to explicit legacy sessions', async (typ, vct) => {
    const session = await initiate();
    const issuerJwt = await resign({ ...decodeJwt(credential.issuerJwt), vct }, typ);
    const token = await presentation(session, { issuerJwt });
    const audience = loadConfig().issuer.url + '/api/oid4vp/client-metadata';
    await expect(verifyPresentation(token, session.nonce, audience, 'AgeCredential', 'openid4vp-1.0')).rejects.toThrow();
    await expect(verifyPresentation(token, session.nonce, audience, 'AgeCredential', 'legacy-draft')).resolves.toEqual({ age_over_18: true });
    expect((await post('/api/oid4vp/response/' + session.sessionId, { vp_token: token })).status).toBe(200);
    const finalResponse = await post('/api/oid4vp/initiate', { credentialType: 'AgeCredential' });
    expect(finalResponse.status).toBe(200);
    const finalSession = await finalResponse.json() as Session;
    const request = await (await fetch(baseUrl + '/api/oid4vp/request/' + finalSession.sessionId)).json() as any;
    const finalToken = await presentation(finalSession, { issuerJwt, kb: { aud: request.client_id } });
    const rejectedFinal = await post('/api/oid4vp/response/' + finalSession.sessionId, { state: finalSession.sessionId, vp_token: { credential: [finalToken] } });
    expect(rejectedFinal.status).toBe(401);
  });
  it('accepts the signed presentation via direct_post form encoding', async () => {
    const session = await initiate();
    const response = await fetch(baseUrl + '/api/oid4vp/response/' + session.sessionId, {
      method: 'POST', body: new URLSearchParams({ vp_token: await presentation(session) }),
    });
    expect(response.status).toBe(200);
  });
  it('creates separate 256-bit session IDs and capabilities, absent from wallet requests', async () => {
    const session = await initiate();
    expect(session.sessionId).toMatch(/^sess-[a-f0-9]{64}$/);
    expect(Buffer.from(session.readToken, 'base64url')).toHaveLength(32);
    expect(Buffer.from(session.nonce, 'base64url')).toHaveLength(32);
    expect(session.requestUri).not.toContain(session.readToken);
    expect(session.qrCodeDataUrl).toMatch(/^data:image\/png;base64,/);
    const request = await (await fetch(baseUrl + '/api/oid4vp/request/' + session.sessionId)).json() as any;
    expect(request.nonce).toBe(session.nonce);
    expect(request.presentation_definition.input_descriptors[0].constraints.fields).toEqual([
      { path: ['$.age_over_18'], intent_to_retain: false },
    ]);
    expect(JSON.stringify(request)).not.toContain(session.readToken);
  });
  it('requires the correct capability before returning any session state', async () => {
    const session = await initiate();
    const other = await initiate();
    expect((await read(session, '')).status).toBe(401);
    expect((await read(session, other.readToken)).status).toBe(401);
    expect((await read(session)).status).toBe(200);
    expect((await read({ ...session, sessionId: 'nonexistent' })).status).toBe(401);
  });
  it('does not trust forwarded headers when generating wallet endpoints', async () => {
    const response = await fetch(baseUrl + '/api/oid4vp/client-metadata', {
      headers: { 'X-Forwarded-Host': 'attacker.invalid', 'X-Forwarded-Proto': 'https', Host: 'attacker.invalid' },
    });
    const metadata = await response.json() as any;
    expect(metadata.client_id).toBe(loadConfig().issuer.url + '/api/oid4vp/client-metadata');
    expect(metadata.vp_formats_supported['dc+sd-jwt']['sd-jwt_alg_values']).toEqual(['ES256']);
  });
  it.each([undefined, '', 'FAKE_JWT~', 'FAKE_JWT~' + disclosure('age_over_18', true) + '~'])('rejects missing/mock presentation %s in test mode', async token => {
    await rejected(await initiate(), token);
  });
  it('rejects an altered disclosure even when the KB-JWT correctly hashes the alteration', async () => {
    const session = await initiate();
    const original = JSON.parse(Buffer.from(selected(credential)[0], 'base64url').toString());
    original[2] = false;
    await rejected(session, await presentation(session, { disclosures: [Buffer.from(JSON.stringify(original)).toString('base64url')] }));
  });
  it('rejects an additional uncommitted disclosure with a valid holder signature', async () => {
    const session = await initiate();
    await rejected(session, await presentation(session, { disclosures: [...selected(credential), disclosure('role', 'admin')] }));
  });
  it.each(['missing', 'wrong'])('rejects %s sd_hash', async variant => {
    const session = await initiate();
    await rejected(session, await presentation(session, variant === 'missing' ? { omitHash: true } : { kb: { sd_hash: hash('other credential') } }));
  });
  it.each([
    ['nonce', { nonce: 'wrong-nonce' }], ['audience', { aud: 'https://attacker.invalid' }],
    ['future iat', { iat: Math.floor(Date.now() / 1000) + 120 }], ['stale iat', { iat: Math.floor(Date.now() / 1000) - 600 }],
  ])('rejects a wrong %s in the holder binding', async (_label, kb) => {
    const session = await initiate();
    await rejected(session, await presentation(session, { kb: kb as JWTPayload }));
  });
  it('rejects a presentation signed by a different holder key', async () => {
    const session = await initiate();
    const rogue = await generateKeyPair('ES256');
    await rejected(session, await presentation(session, { signingKey: rogue.privateKey }));
  });
  it('rejects an issuer signature by an untrusted key', async () => {
    const session = await initiate();
    const rogue = await generateKeyPair('ES256');
    const issuerJwt = await new SignJWT(decodeJwt(credential.issuerJwt)).setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' }).sign(rogue.privateKey);
    await rejected(session, await presentation(session, { issuerJwt }));
  });
  it.each(['iss', 'vct'])('rejects a signed credential with the wrong %s', async field => {
    const session = await initiate();
    const issuerJwt = await resign({ ...decodeJwt(credential.issuerJwt), [field]: 'untrusted-value' });
    await rejected(session, await presentation(session, { issuerJwt }));
  });
  it('rejects duplicate disclosures', async () => {
    const session = await initiate();
    const d = selected(credential)[0];
    await rejected(session, await presentation(session, { disclosures: [d, d] }));
  });
  it.each(['age_over_18', '__proto__', 'constructor', 'prototype', 'iss', '_sd'])('rejects committed duplicate/reserved claim %s', async name => {
    const session = await initiate();
    const extra = disclosure(name, 'injected', 'different-salt');
    const payload = decodeJwt(credential.issuerJwt);
    const issuerJwt = await resign({ ...payload, _sd: [...payload._sd as string[], hash(extra)] });
    await rejected(session, await presentation(session, { issuerJwt, disclosures: [...selected(credential), extra] }));
  });
  it('requires the requested age claim and a true age predicate', async () => {
    const missing = await initiate();
    await rejected(missing, await presentation(missing, { disclosures: [] }));
    const underage = await issue((new Date().getUTCFullYear() - 10) + '-01-01');
    const session = await initiate();
    await rejected(session, await presentation(session, { source: underage }));
  });
  it('rejects revoked credentials even with a fresh valid holder binding', async () => {
    const source = await issue();
    expect(revokeCredential(decodeJwt(source.issuerJwt).jti!)).toBe(true);
    const session = await initiate();
    await rejected(session, await presentation(session, { source }));
  });
  it('rejects retired status lists even when the recorded credential is not individually revoked', async () => {
    const source = await issue(); const session = await initiate();
    const statusPath = join(process.env.DATA_DIR!, 'statuslist.json');
    const previous = readFileSync(statusPath, 'utf8');
    const status = JSON.parse(previous);
    const entry = status.issuedCredentials.find((record: any) => record.credentialId === decodeJwt(source.issuerJwt).jti);
    expect(entry.revoked).toBe(false);
    status.retiredListIds = [...status.retiredListIds ?? [], entry.listId];
    writeFileSync(statusPath, JSON.stringify(status));
    try { await rejected(session, await presentation(session, { source })); }
    finally { writeFileSync(statusPath, previous); }
  });
  it('accepts only the issuer and status representation selected by the runtime wallet profile', async () => {
    const session = await initiate(); const config = loadConfig();
    const audience = config.issuer.url + '/api/oid4vp/client-metadata';
    const customToken = await presentation(session);
    const payload: JWTPayload = { ...decodeJwt(credential.issuerJwt), iss: config.issuer.url };
    const entry = getIssuedCredentials().find(record => record.credentialId === payload.jti)!;
    delete payload.credentialStatus;
    const status = { status_list: { idx: entry.statusIndex, uri: config.issuer.url + '/status/token/' + entry.listId } };
    const issuerJwt = await resign({ ...payload, status });
    const eudiToken = await presentation(session, { issuerJwt });
    await expect(verifyPresentation(eudiToken, session.nonce, audience, 'AgeCredential')).rejects.toThrow();
    vi.stubEnv('WALLET_PROFILE', 'eudi-android');
    await expect(verifyPresentation(customToken, session.nonce, audience, 'AgeCredential')).rejects.toThrow();
    await expect(verifyPresentation(eudiToken, session.nonce, audience, 'AgeCredential')).resolves.toEqual({ age_over_18: true });
    for (const wrong of [
      { status_list: { ...status.status_list, idx: String(entry.statusIndex) } },
      { status_list: { ...status.status_list, uri: config.issuer.url + '/status/' + entry.listId } },
    ]) {
      const badIssuer = await resign({ ...payload, status: wrong });
      await expect(verifyPresentation(await presentation(session, { issuerJwt: badIssuer }), session.nonce, audience, 'AgeCredential')).rejects.toThrow();
    }
  });
  it('consumes an issuance nonce once when the same valid proof arrives concurrently', async () => {
    const keys = await generateKeyPair('ES256');
    const jwk = await exportJWK(keys.publicKey);
    const tokenResponse = await post('/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': issuePreAuthCode({ id: 'concurrency-holder', dateOfBirth: '1990-01-01' }, 'AgeCredential'),
    });
    expect(tokenResponse.status).toBe(200);
    const token = await tokenResponse.json() as any;
    const proof = await new SignJWT({ nonce: token.c_nonce }).setAudience(loadConfig().issuer.url).setIssuedAt()
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk }).sign(keys.privateKey);
    const initialCount = getIssuedCredentials().length;
    const issueRequest = () => fetch(baseUrl + '/credentials', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token.access_token },
      body: JSON.stringify({ proof: { proof_type: 'jwt', jwt: proof } }),
    });
    const responses = await Promise.all(Array.from({ length: 4 }, issueRequest));
    expect(responses.filter(response => response.status === 200)).toHaveLength(1);
    for (const response of responses.filter(response => response.status !== 200)) {
      expect([400, 409]).toContain(response.status);
      expect(['issuance_in_progress', 'invalid_nonce']).toContain((await response.json() as any).error);
    }
    expect(getIssuedCredentials()).toHaveLength(initialCount + 1);
    expect((await issueRequest()).status).toBe(400);
  });
  it('allows exactly one concurrent response and rejects later replay', async () => {
    const session = await initiate();
    const token = await presentation(session);
    const responses = await Promise.all(Array.from({ length: 4 }, () => post('/api/oid4vp/response/' + session.sessionId, { vp_token: token })));
    expect(responses.map(r => r.status).sort()).toEqual([200, 409, 409, 409]);
    expect((await post('/api/oid4vp/response/' + session.sessionId, { vp_token: token })).status).toBe(409);
    expect((await fetch(baseUrl + '/api/oid4vp/request/' + session.sessionId)).status).toBe(404);
  });
  it('enforces TTL on reads, wallet requests and submissions without requiring a write', async () => {
    const session = await initiate();
    const token = await presentation(session);
    const future = Date.now() + 30 * 60_000 + 1;
    vi.spyOn(Date, 'now').mockReturnValue(future);
    expect((await read(session)).status).toBe(401);
    expect((await fetch(baseUrl + '/api/oid4vp/request/' + session.sessionId)).status).toBe(404);
    expect((await post('/api/oid4vp/response/' + session.sessionId, { vp_token: token })).status).toBe(404);
  });
  it('preserves concurrent sessions and encrypts capabilities and claims at rest', async () => {
    const sessions = await Promise.all(Array.from({ length: 8 }, initiate));
    expect(new Set(sessions.map(s => s.sessionId)).size).toBe(8);
    for (const session of sessions) expect((await read(session)).status).toBe(200);
    const raw = readFileSync(join(process.env.DATA_DIR!, 'oid4vp_sessions.json'), 'utf8');
    const envelope = JSON.parse(raw);
    expect(envelope).toMatchObject({ version: 2, iv: expect.any(String), tag: expect.any(String), content: expect.any(String) });
    for (const session of sessions) {
      expect(raw).not.toContain(session.sessionId);
      expect(raw).not.toContain(session.readToken);
    }
    expect(raw).not.toContain('age_over_18');
  });
});
