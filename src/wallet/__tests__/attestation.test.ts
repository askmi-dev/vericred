import { beforeAll, beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { writeFileSync } from 'node:fs';
import { generateKeyPair, exportJWK, SignJWT, type JWTPayload } from 'jose';
import { attestationFixture } from '../../../tests/helpers/attestation-fixture.js';
import { inspectAttestationPolicy, loadAttestationPolicy, attestationRequirements } from '../attestation.js';
import { verifyHolderProofJwt } from '../../oid4vci/proof.js';

let fixture: Awaited<ReturnType<typeof attestationFixture>>;
let holder: Awaited<ReturnType<typeof generateKeyPair>>;
let jwk: Awaited<ReturnType<typeof exportJWK>>;
let fetcher: ReturnType<typeof vi.fn>;
let statusJwt: string;
const audience = 'https://issuer.example.invalid';
const nonce = 'fresh-issuer-nonce';
const lifetime = 86400;
const previous = process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH;
async function proof(payload: JWTPayload = {}, options: { header?: Record<string, unknown>; attestationHeader?: Record<string, unknown>; attestation?: string } = {}) {
  const attestation = options.attestation ?? await fixture.attestation([jwk], nonce, payload, options.attestationHeader);
  return new SignJWT({ aud: audience, nonce, iat: Math.floor(Date.now() / 1000) })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', kid: '0', key_attestation: attestation, ...options.header }).sign(holder.privateKey);
}
const verify = (token: string) => verifyHolderProofJwt(token, audience, nonce, lifetime);
beforeAll(async () => { fixture = await attestationFixture(); holder = await generateKeyPair('ES256', { extractable: true }); jwk = await exportJWK(holder.publicKey); });
beforeEach(async () => {
  fixture.provision(); statusJwt = await fixture.statusToken();
  fetcher = vi.fn(async () => new Response(statusJwt, { headers: { 'Content-Type': 'application/statuslist+jwt' } }));
  vi.stubGlobal('fetch', fetcher);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); if (previous === undefined) delete process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH; else process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH = previous; });

describe('Policy-backed attested key proofs (synthetic provider and status transport)', () => {
  it('authenticates separate provider/status signers, binds PoP, and exposes only the public holder key', async () => {
    const result = await verify(await proof());
    expect(result.jwk).toEqual(jwk); expect(result.keyStorageExpiresAt).toBeGreaterThan(Date.now() / 1000 + lifetime);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith(fixture.statusUri, expect.objectContaining({ redirect: 'error', credentials: 'omit', cache: 'no-store' }));
    expect(JSON.stringify(result)).not.toContain(fixture.policy.providers[0].id);
    expect(attestationRequirements(lifetime)).toEqual({ key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'], preferred_key_storage_status_period: lifetime });
  });
  it('supports the JWT-proof contract where KA nonce is absent and outer PoP still binds the issuer nonce', async () => {
    const attestation = await fixture.attestation([jwk], undefined);
    expect((await verify(await proof({}, { attestation }))).jwk).toEqual(jwk);
  });
  it('requires provisioned policy without exposing a path or private parse error', async () => {
    process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH = fixture.dir + '/missing-private-policy.json';
    expect(inspectAttestationPolicy()).toEqual({ configured: true, valid: false, providerCount: 0 });
    expect(() => loadAttestationPolicy()).toThrow('missing or invalid');
    await expect(verify(await proof())).rejects.toThrow('could not be validated');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('rejects duplicate ambiguous pins and unreviewed policy fields', () => {
    writeFileSync(fixture.policyPath, JSON.stringify({ ...fixture.policy, providers: [...fixture.policy.providers, ...fixture.policy.providers] }));
    expect(() => loadAttestationPolicy()).toThrow();
    writeFileSync(fixture.policyPath, JSON.stringify({ ...fixture.policy, trustAnySigner: true }));
    expect(() => loadAttestationPolicy()).toThrow();
  });
  it.each(['1', '00', '-1', '999999999', undefined])('rejects non-profile key index %s', async kid => {
    await expect(verify(await proof({}, { header: { kid } }))).rejects.toThrow(); expect(fetcher).not.toHaveBeenCalled();
  });
  it.each(['jwk', 'jku', 'x5u', 'x5c'])('rejects conflicting outer key selector %s', async selector => {
    await expect(verify(await proof({}, { header: { [selector]: selector === 'jwk' ? jwk : 'unexpected' } }))).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('does not fetch status for an invalid outer signature, wrong audience or nonce', async () => {
    const token = await proof(); const pieces = token.split('.');
    pieces[1] = Buffer.from(JSON.stringify({ aud: audience, nonce, iat: 1 })).toString('base64url');
    await expect(verify(pieces.join('.'))).rejects.toThrow();
    await expect(verifyHolderProofJwt(token, 'https://wrong.example.invalid', nonce, lifetime)).rejects.toThrow();
    await expect(verifyHolderProofJwt(token, audience, 'other-nonce', lifetime)).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('rejects an untrusted attestation certificate even with a valid signature', async () => {
    const attestation = await fixture.attestation([jwk], nonce, {}, {}, fixture.status);
    await expect(verify(await proof({}, { attestation }))).rejects.toThrow(); expect(fetcher).not.toHaveBeenCalled();
  });
  it('rejects an altered attestation payload', async () => {
    const parts = (await fixture.attestation([jwk], nonce)).split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()); payload.certification = fixture.certification + '/altered';
    parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
    await expect(verify(await proof({}, { attestation: parts.join('.') }))).rejects.toThrow(); expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([
    ['expired', { exp: 1 }], ['missing expiry', { exp: undefined }], ['wrong nonce', { nonce: 'different' }],
    ['future issuance', { iat: Math.floor(Date.now() / 1000) + 120 }], ['old issuance', { iat: Math.floor(Date.now() / 1000) - 301 }],
    ['missing attested key', { attested_keys: [] }], ['unapproved assurance', { key_storage: ['iso_18045_basic'] }],
    ['missing user assurance', { user_authentication: [] }], ['unapproved certification', { certification: 'https://attacker.invalid/cert' }],
    ['missing storage status', { key_storage_status: undefined }],
    ['insufficient maintenance', { key_storage_status: { exp: 1, status: { status_list: { idx: 0, uri: 'https://wallet-status.example.invalid/lists/one' } } } }],
    ['unapproved status URL', { key_storage_status: { exp: 9999999999, status: { status_list: { idx: 0, uri: 'https://attacker.invalid/lists/one' } } } }],
    ['encoded status traversal', { key_storage_status: { exp: 9999999999, status: { status_list: { idx: 0, uri: 'https://wallet-status.example.invalid/lists/%2f..%2fadmin' } } } }],
    ['lookalike status path', { key_storage_status: { exp: 9999999999, status: { status_list: { idx: 0, uri: 'https://wallet-status.example.invalid/lists-evil/one' } } } }],
    ['status index outside bitmap', { key_storage_status: { exp: 9999999999, status: { status_list: { idx: 9, uri: 'https://wallet-status.example.invalid/lists/one' } } } }],
  ])('fails closed for %s', async (_name, payload) => { await expect(verify(await proof(payload))).rejects.toThrow(); });
  it('rejects private attested material and the wrong outer holder key', async () => {
    await expect(verify(await proof({ attested_keys: [await exportJWK(holder.privateKey)] }))).rejects.toThrow();
    const other = await generateKeyPair('ES256');
    await expect(verify(await proof({ attested_keys: [await exportJWK(other.publicKey)] }))).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([1, 2, 4, 8])('verifies signed %i-bit status and rejects every nonzero state', async bits => {
    statusJwt = await fixture.statusToken({}, Buffer.from([0]), bits); await expect(verify(await proof())).resolves.toBeDefined();
    statusJwt = await fixture.statusToken({}, Buffer.from([1]), bits); await expect(verify(await proof())).rejects.toThrow('status');
  });
  it.each(['expiry', 'TTL', 'max age'])('rejects the first status crossing its %s deadline during the second fetch', async deadline => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const startedAt = Date.now(); const now = Math.floor(startedAt / 1000);
    const otherUri = fixture.statusUri + '-other';
    const first = await fixture.statusToken({
      iat: deadline === 'max age' ? now - 119 : now,
      exp: deadline === 'expiry' ? now + 2 : now + 120,
      ttl: deadline === 'TTL' ? 2 : undefined,
    });
    const second = await fixture.statusToken({ sub: otherUri });
    fetcher.mockImplementation(async (uri: string) => {
      if (uri === otherUri) vi.setSystemTime(startedAt + 3000);
      return new Response(uri === otherUri ? second : first, { headers: { 'Content-Type': 'application/statuslist+jwt' } });
    });
    await expect(verify(await proof({ status: { status_list: { idx: 0, uri: otherUri } } }))).rejects.toThrow('status');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('accepts both statuses while their deadlines remain current at completion', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const startedAt = Date.now(); const now = Math.floor(startedAt / 1000);
    const otherUri = fixture.statusUri + '-other';
    const first = await fixture.statusToken({ exp: now + 4, ttl: 4 });
    const second = await fixture.statusToken({ sub: otherUri });
    fetcher.mockImplementation(async (uri: string) => {
      if (uri === otherUri) vi.setSystemTime(startedAt + 3000);
      return new Response(uri === otherUri ? second : first, { headers: { 'Content-Type': 'application/statuslist+jwt' } });
    });
    await expect(verify(await proof({ status: { status_list: { idx: 0, uri: otherUri } } }))).resolves.toBeDefined();
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('rejects the attestation crossing its maximum age while status is fetched', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    const startedAt = Date.now(); const now = Math.floor(startedAt / 1000);
    fetcher.mockImplementation(async () => {
      vi.setSystemTime(startedAt + 3000);
      return new Response(statusJwt, { headers: { 'Content-Type': 'application/statuslist+jwt' } });
    });
    await expect(verify(await proof({ iat: now - 299 }))).rejects.toThrow('status');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('rejects policy removal during status validation', async () => {
    fetcher.mockImplementation(async () => { writeFileSync(fixture.policyPath, '{}'); return new Response(statusJwt, { headers: { 'Content-Type': 'application/statuslist+jwt' } }); });
    await expect(verify(await proof())).rejects.toThrow('status');
  });
  it('rejects the attestation signer used as an unapproved status signer', async () => {
    statusJwt = await fixture.statusToken({}, Buffer.from([0]), 1, fixture.provider);
    await expect(verify(await proof())).rejects.toThrow('status');
  });
  it.each([
    ['wrong subject', { sub: 'https://wallet-status.example.invalid/lists/other' }], ['expired', { exp: 1 }],
    ['stale', { iat: Math.floor(Date.now() / 1000) - 121 }], ['expired TTL', { iat: Math.floor(Date.now() / 1000) - 2, ttl: 1 }],
    ['unsupported bit width', { status_list: { bits: 3, lst: 'abc' } }], ['invalid compressed data', { status_list: { bits: 1, lst: 'invalid' } }],
  ])('rejects %s status tokens', async (_name, payload) => { statusJwt = await fixture.statusToken(payload); await expect(verify(await proof())).rejects.toThrow('status'); });
  it('bounds decompression and fetch size', async () => {
    statusJwt = await fixture.statusToken({}, Buffer.alloc(1024 * 1024 + 1));
    await expect(verify(await proof())).rejects.toThrow('status');
    statusJwt = 'x'.repeat(128 * 1024 + 1);
    await expect(verify(await proof())).rejects.toThrow('status');
  });
  it.each([302, 404, 503])('rejects status HTTP %i without following redirects', async status => {
    fetcher.mockImplementation(async () => new Response('', { status, headers: { Location: 'https://attacker.invalid', 'Content-Type': 'application/statuslist+jwt' } }));
    await expect(verify(await proof())).rejects.toThrow('status');
  });
  it('rejects wrong media type and unavailable status without leaking network errors', async () => {
    fetcher.mockImplementationOnce(async () => new Response(statusJwt, { headers: { 'Content-Type': 'text/html' } }));
    await expect(verify(await proof())).rejects.toThrow('status');
    fetcher.mockRejectedValue(new Error('private-network-sentinel'));
    const error = await verify(await proof()).catch(error => error);
    expect(error.message).toBe('Wallet key attestation status could not be validated');
  });
});
