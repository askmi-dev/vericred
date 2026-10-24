/**
 * #31 — Restart-survival of the offer/token state store.
 *
 * Acceptance criterion: a gateway restart does not lose pending offers.
 * We prove it at the store level: put a pre-auth code into a FileOfferStore,
 * construct a fresh instance over the same DATA_DIR (≡ process restart),
 * and redeem it. Plus: token round-trip, expiry sweep, corrupt-file
 * resilience, and single-use semantics across restarts.
 *
 * #37 review: instances now hold a single-writer lock, so every
 * simulated-restart step releases the lock first (≡ the old process
 * ending) before the fresh instance is constructed.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { FileOfferStore, InMemoryOfferStore } from '../state-store.js';

const TEMP = './src/oid4vci/__tests__/temp-store-restart';

function entry(expiresAt = Date.now() + 10 * 60 * 1000) {
  return {
    holderData: { id: 'h1', email: 'h1@example.com' },
    expiresAt,
    credentialType: 'AgeCredential',
  };
}

describe('#31: OfferStore implementations', () => {
  beforeEach(() => {
    process.env['DATA_DIR'] = TEMP;
    rmSync(TEMP, { recursive: true, force: true });
    mkdirSync(TEMP, { recursive: true });
  });
  afterEach(() => {
    rmSync(TEMP, { recursive: true, force: true });
    delete process.env['DATA_DIR'];
  });

  it('pre-auth code survives a simulated restart (FileOfferStore)', () => {
    const s1 = new FileOfferStore(TEMP);
    s1.putPreAuthCode('code-abc', entry());
    s1.releaseLock(); // old process ends
    // Fresh instance over the same files ≡ process restart
    const s2 = new FileOfferStore(TEMP);
    const redeemed = s2.takePreAuthCode('code-abc');
    expect(redeemed).not.toBeNull();
    expect(redeemed!.holderData['id']).toBe('h1');
    expect(redeemed!.credentialType).toBe('AgeCredential');
    s2.releaseLock();
    // single-use: a third instance must not see it again
    expect(new FileOfferStore(TEMP).takePreAuthCode('code-abc')).toBeNull();
  });

  it('access token round-trips across restart, nonce rotation persists', () => {
    const s1 = new FileOfferStore(TEMP);
    s1.putAccessToken('tok-1', {
      holderData: { id: 'h1' }, expiresAt: Date.now() + 5 * 60 * 1000,
      cNonce: 'n1', cNonceExpiresAt: Date.now() + 300000,
      credentialType: 'AgeCredential',
    });
    s1.releaseLock();
    const s2 = new FileOfferStore(TEMP);
    const tok = s2.getAccessToken('tok-1');
    expect(tok).not.toBeNull();
    tok!.cNonce = 'n2';
    tok!.cNonceExpiresAt = Date.now() + 300000;
    s2.putAccessToken('tok-1', tok!);
    s2.releaseLock();
    expect(new FileOfferStore(TEMP).getAccessToken('tok-1')!.cNonce).toBe('n2');
  });

  it('sweep evicts expired entries and persists the eviction', () => {
    const s1 = new FileOfferStore(TEMP);
    s1.putPreAuthCode('old', entry(Date.now() - 1000));
    s1.putPreAuthCode('fresh', entry());
    const swept = s1.sweep(Date.now());
    expect(swept.preAuthCodes).toBe(1);
    s1.releaseLock();
    const s2 = new FileOfferStore(TEMP);
    expect(s2.takePreAuthCode('old')).toBeNull();
    expect(s2.takePreAuthCode('fresh')).not.toBeNull();
  });

  it('corrupt state file fails open: start empty, never throw', () => {
    writeFileSync(`${TEMP}/offer-state.json`, '{not json');
    const s = new FileOfferStore(TEMP);
    expect(s.takePreAuthCode('anything')).toBeNull();
    s.releaseLock();
  });

  it('InMemoryOfferStore keeps original behavior (no persistence)', () => {
    const m = new InMemoryOfferStore();
    m.putPreAuthCode('c', entry());
    expect(m.takePreAuthCode('c')).not.toBeNull();
    expect(m.takePreAuthCode('c')).toBeNull();
    const p = `${TEMP}/offer-state.json`;
    expect(existsSync(p)).toBe(false);
  });
});
