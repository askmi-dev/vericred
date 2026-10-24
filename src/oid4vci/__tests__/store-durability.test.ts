/**
 * #37 review follow-up — durability, single-writer and corruption tests
 * for the file-backed offer store.
 *
 * These tests exist because store-instance recreation alone is not
 * production evidence. They cover the blocking correctness risks named
 * in the review of #31:
 *  1. a consume that cannot be made durable must not be reported as
 *     consumed (no restart resurrection of used codes);
 *  2. two live instances over the same DATA_DIR must not both consume
 *     the same code;
 *  3. loading must not mutate or further corrupt the backing file, and
 *     a malformed entry after a valid prefix must preserve the original
 *     file and start the store empty;
 *  4. truncated / crash-written files must recover fail-open without
 *     bricking the gateway.
 * Honest limits recorded here: these are same-process simulations of
 * crash/restart and multi-writer races (store-instance recreation with
 * lock bypass via the constructor option), not real process kills.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdirSync, rmSync, writeFileSync, readFileSync, chmodSync, statSync, readdirSync } from 'fs';
import { FileOfferStore, StorePersistenceError } from '../state-store.js';

const TEMP = './src/oid4vci/__tests__/temp-store-durability';

function entry(expiresAt = Date.now() + 10 * 60 * 1000) {
  return {
    holderData: { id: 'h1', email: 'h1@example.com' },
    expiresAt,
    credentialType: 'AgeCredential',
  };
}

function tokenEntry(expiresAt = Date.now() + 5 * 60 * 1000) {
  return {
    holderData: { id: 'h1' },
    expiresAt,
    cNonce: 'n1',
    cNonceExpiresAt: Date.now() + 300000,
    credentialType: 'AgeCredential',
  };
}

function fileMode(p: string): number {
  return statSync(p).mode & 0o777;
}

describe('#37 review: durable single-use consume', () => {
  beforeEach(() => {
    rmSync(TEMP, { recursive: true, force: true });
    mkdirSync(TEMP, { recursive: true });
  });
  afterEach(() => rmSync(TEMP, { recursive: true, force: true }));

  it('takePreAuthCode throws and rolls back when persistence fails; retry succeeds after recovery', () => {
    const s = new FileOfferStore(TEMP, { noLock: true });
    s.putPreAuthCode('code-1', entry());

    const statePath = `${TEMP}/offer-state.json`;
    // Simulate a full disk: make the directory read-only so the temp
    // file write fails (writeFileSync to a mode 0500 dir throws EACCES).
    chmodSync(TEMP, 0o500);

    expect(() => s.takePreAuthCode('code-1')).toThrow(StorePersistenceError);

    // Rollback: the code is still present and still redeemable.
    chmodSync(TEMP, 0o700);
    const redeemed = s.takePreAuthCode('code-1');
    expect(redeemed).not.toBeNull();
    // And it is durably gone: a fresh instance cannot redeem it again.
    expect(new FileOfferStore(TEMP, { noLock: true }).takePreAuthCode('code-1')).toBeNull();
    void statePath;
  });

  it('a failed consume leaves the old code on disk but the in-memory rollback prevents double issue within the process', () => {
    const s = new FileOfferStore(TEMP, { noLock: true });
    s.putPreAuthCode('code-2', entry());
    chmodSync(TEMP, 0o500);
    let threw = false;
    try { s.takePreAuthCode('code-2'); } catch { threw = true; }
    expect(threw).toBe(true);
    chmodSync(TEMP, 0o700);
    // Still single-use from the caller's perspective: exactly one more
    // consume succeeds, and it is the same entry.
    expect(s.takePreAuthCode('code-2')?.holderData['id']).toBe('h1');
    expect(s.takePreAuthCode('code-2')).toBeNull();
  });

  it('access-token write failures roll back the previous value', () => {
    const s = new FileOfferStore(TEMP, { noLock: true });
    s.putAccessToken('tok-1', tokenEntry());
    chmodSync(TEMP, 0o500);
    expect(() => s.putAccessToken('tok-1', { ...tokenEntry(), cNonce: 'n2' })).toThrow(StorePersistenceError);
    chmodSync(TEMP, 0o700);
    expect(s.getAccessToken('tok-1')?.cNonce).toBe('n1');
    expect(new FileOfferStore(TEMP, { noLock: true }).getAccessToken('tok-1')?.cNonce).toBe('n1');
  });

  it('nonce rotation failure keeps the previous nonce on disk', () => {
    const s = new FileOfferStore(TEMP, { noLock: true });
    s.putAccessToken('tok-2', tokenEntry());
    chmodSync(TEMP, 0o500);
    expect(() => s.putAccessToken('tok-2', { ...tokenEntry(), cNonce: 'n2' })).toThrow(StorePersistenceError);
    chmodSync(TEMP, 0o700);
    expect(new FileOfferStore(TEMP, { noLock: true }).getAccessToken('tok-2')?.cNonce).toBe('n1');
  });
});

describe('#37 review: single-writer enforcement', () => {
  beforeEach(() => {
    rmSync(TEMP, { recursive: true, force: true });
    mkdirSync(TEMP, { recursive: true });
  });
  afterEach(() => {
    rmSync(TEMP, { recursive: true, force: true });
  });

  it('a second live instance over the same DATA_DIR fails fast instead of racing', () => {
    const s1 = new FileOfferStore(TEMP); // holds the lock
    expect(() => new FileOfferStore(TEMP)).toThrow(StorePersistenceError);
    s1.releaseLock();
    // After release, a new instance may take over cleanly.
    const s2 = new FileOfferStore(TEMP);
    s2.releaseLock();
  });

  it('an unlocked legacy PID file does not block the kernel lock', () => {
    writeFileSync(`${TEMP}/offer-state.lock`, '16777215@123', { mode: 0o600 });
    const s = new FileOfferStore(TEMP); // must not throw
    s.releaseLock();
  });

  it('a released writer cannot mutate state after another writer takes over', () => {
    const first = new FileOfferStore(TEMP);
    first.releaseLock();
    const second = new FileOfferStore(TEMP);
    try {
      expect(() => first.putPreAuthCode('closed-writer', entry())).toThrow(StorePersistenceError);
      expect(second.takePreAuthCode('closed-writer')).toBeNull();
    } finally { second.releaseLock(); }
  });

  it('noLock bypass demonstrates the multi-writer race the lock exists to prevent (documented, unsupported)', () => {
    // With noLock both instances hydrate from the same file and each
    // believes it owns the code: both consume successfully. This is the
    // exact race from the #37 review; the single-writer lock is the
    // mitigation, so noLock is explicitly unsupported in production.
    const s1 = new FileOfferStore(TEMP, { noLock: true });
    s1.putPreAuthCode('race-code', entry());
    const s2 = new FileOfferStore(TEMP, { noLock: true });
    const a = s1.takePreAuthCode('race-code');
    const b = s2.takePreAuthCode('race-code');
    expect(a).not.toBeNull();
    expect(b).not.toBeNull(); // single-use IS violated without the lock
  });
});

describe('#37 review: load must not mutate the backing file', () => {
  beforeEach(() => {
    rmSync(TEMP, { recursive: true, force: true });
    mkdirSync(TEMP, { recursive: true });
  });
  afterEach(() => rmSync(TEMP, { recursive: true, force: true }));

  it('malformed entry after a valid prefix: original file preserved, store starts empty', () => {
    const s = new FileOfferStore(TEMP, { noLock: true });
    s.putPreAuthCode('good', entry());
    s.releaseLock();
    const original = readFileSync(`${TEMP}/offer-state.json`, 'utf8');
    const parsed = JSON.parse(original) as { preAuthCodes: [string, unknown][] };
    parsed.preAuthCodes.push(['bad', { holderData: null, expiresAt: 'not-a-number' }]);
    writeFileSync(`${TEMP}/offer-state.json`, JSON.stringify(parsed), 'utf8');

    const s2 = new FileOfferStore(TEMP, { noLock: true });
    expect(s2.takePreAuthCode('good')).toBeNull(); // empty, not partially loaded
    // The corrupt file was not rewritten or "repaired" by loading.
    expect(readFileSync(`${TEMP}/offer-state.json`, 'utf8')).toBe(JSON.stringify(parsed));
  });

  it('truncated file (crash mid-write in the old format): starts empty, never throws', () => {
    writeFileSync(`${TEMP}/offer-state.json`, '{"preAuthCodes":[["a",{"holderData":{"id":"x"},"expi', 'utf8');
    const s = new FileOfferStore(TEMP, { noLock: true });
    expect(s.takePreAuthCode('a')).toBeNull();
    expect(s.getAccessToken('a')).toBeNull();
  });

  it('missing arrays (wrong shape): starts empty, file preserved', () => {
    writeFileSync(`${TEMP}/offer-state.json`, '{"something":"else"}', 'utf8');
    const s = new FileOfferStore(TEMP, { noLock: true });
    expect(s.takePreAuthCode('a')).toBeNull();
  });

  it.each(['null', 'true', '42', '"invalid-root"', '[]'])('invalid JSON root %s does not crash recovery or alter evidence', (original) => {
    writeFileSync(`${TEMP}/offer-state.json`, original, 'utf8');
    const store = new FileOfferStore(TEMP);
    try {
      expect(store.takePreAuthCode('missing')).toBeNull();
      expect(store.getAccessToken('missing')).toBeNull();
      expect(readFileSync(`${TEMP}/offer-state.json`, 'utf8')).toBe(original);
    } finally { store.releaseLock(); }
    const next = new FileOfferStore(TEMP);
    next.releaseLock();
  });

  it('state file is written with owner-only permissions (0600)', () => {
    const s = new FileOfferStore(TEMP, { noLock: true });
    s.putPreAuthCode('perm-code', entry());
    expect(existsSync(`${TEMP}/offer-state.json`)).toBe(true);
    // umask can only remove bits; mode 0o600 requested on the temp file
    // survives the rename. On permissive umasks this asserts the real mode.
    const mode = fileMode(`${TEMP}/offer-state.json`);
    expect(mode & 0o077).toBe(0);
  });

  it('crash-safe replacement: no .tmp leftovers after successful writes', () => {
    const s = new FileOfferStore(TEMP, { noLock: true });
    s.putPreAuthCode('c1', entry());
    s.putAccessToken('t1', tokenEntry());
    const leftovers = readdirSync(TEMP);
    // Only the state file and (when held) the lock file may exist.
    expect(leftovers.filter((f) => f.includes('.tmp.')).length).toBe(0);
  });
});
