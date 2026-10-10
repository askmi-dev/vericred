/**
 * KeyProvider tests (#19): provider selection is fail-closed; the file provider
 * preserves manager semantics (kid stability, rotation, history listing).
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { createProvider, resetKeyProviderCache, getKeyProvider } from './index.js';

describe('key provider factory', () => {
  beforeEach(() => resetKeyProviderCache());

  it('selects the file provider by default (no config)', async () => {
    const provider = await getKeyProvider();
    expect(provider.name).toBe('file');
  });

  it('fails closed on unknown provider type', () => {
    expect(() => createProvider('hardware' as never)).toThrow(/Unknown key provider/u);
    expect(() => createProvider('' as never)).toThrow(/Unknown key provider/u);
  });

  it('kms provider fails closed until implemented', () => {
    expect(() => createProvider('kms')).toThrow(/not implemented/u);
  });
});

describe('file provider semantics', () => {
  beforeEach(() => resetKeyProviderCache());

  it('exposes a stable kid across calls', async () => {
    const provider = await getKeyProvider();
    const kid1 = await provider.getKid();
    const kid2 = await provider.getKid();
    expect(kid1).toBe(kid2);
    expect(kid1).toBeTruthy();
  });

  it('lists public keys including rotation history', async () => {
    const provider = await getKeyProvider();
    const before = await provider.listPublicKeys();
    expect(before.length).toBeGreaterThan(0);

    const newKid = await provider.rotate();
    const after = await provider.listPublicKeys();
    // Active key changed, old key stays published for verification.
    expect(after.some((k) => k.kid === newKid)).toBe(true);
    expect(after.length).toBeGreaterThan(before.length);
  });

  it('signs payloads as compact ES256 JWS with kid header', async () => {
    const provider = await getKeyProvider();
    const jws = await provider.sign(JSON.stringify({ sub: 'test' }));
    expect(jws.split('.').length).toBe(3);
    const [h] = jws.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf-8'));
    expect(header.alg).toBe('ES256');
    expect(header.kid).toBeTruthy();
  });
});
