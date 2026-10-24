/**
 * Persistent offer/token state store (#31).
 *
 * Pre-auth codes and access tokens previously lived in in-memory Maps:
 * a container restart killed every pending offer and horizontal scaling
 * was impossible. This module defines the OfferStore interface those Maps
 * hid behind, plus the default file-backed implementation (same
 * DATA_DIR persistence pattern as statuslist.json / runtime.json — zero
 * new dependencies).
 *
 * Security model (review of #37):
 * - Single-use consume is durably atomic: takePreAuthCode only reports
 *   success after the removal has been written to disk. If persistence
 *   fails, the in-memory removal is rolled back and StorePersistenceError
 *   is thrown, so a restart can never resurrect a code the caller
 *   believes consumed, and no token is issued for a non-durable consume.
 * - Writes are crash-safe: each mutation serializes the full state to a
 *   temp file and renames it over the live file. A crash mid-write
 *   leaves the previous complete state intact.
 * - Loading never mutates the backing file: state is parsed and validated
 *   completely in memory before it is installed. A corrupt or partial
 *   file starts the store empty (fail open, logged loudly) and the
 *   original file is preserved untouched for operator inspection.
 * - Single writer only: an OS advisory lock is held on a stable inode
 *   for the store lifetime. The kernel releases it on process death;
 *   neither PID reuse nor simultaneous startup requires stale reclaim.
 *
 * Security note: access tokens are bearer credentials and are stored in
 * DATA_DIR. That directory already holds issuer keys and admin secrets
 * and must be treated as private infrastructure state; deployments with
 * stricter needs can implement the interface against Redis/pg (see
 * issue #31) via `createOfferStore` selection.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync, openSync, closeSync, fsyncSync } from 'fs';
import { randomUUID } from 'crypto';
import { flockSync } from 'fs-ext';

export interface PreAuthCodeEntry {
  holderData: Record<string, unknown>;
  expiresAt: number;
  credentialType?: string;
  claims?: Record<string, unknown>;
  /** #26: Art. 6a audit context, carried from offer creation to issuance. */
  provenance?: ProvenanceContext;
}

export interface StoredAccessToken {
  holderData: Record<string, unknown>;
  expiresAt: number;
  cNonce: string;
  cNonceExpiresAt: number;
  credentialType?: string;
  claims?: Record<string, unknown>;
  /** #26: Art. 6a audit context, carried from offer creation to issuance. */
  provenance?: ProvenanceContext;
}

export interface ProvenanceContext {
  connectorType: 'json' | 'postgres' | 'mysql' | 'rest' | 'csv' | 'manual';
  sourceRef: string;
  verificationMode: 'authoritative-source' | 'admin-attested';
  identifierHash: string;
  lookupAt: string;
}

export class StorePersistenceError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = 'StorePersistenceError';
  }
}

export interface OfferStore {
  putPreAuthCode(code: string, entry: PreAuthCodeEntry): void;
  /**
   * Get + delete atomically: pre-auth codes are single-use.
   * @throws StorePersistenceError when the removal cannot be made
   * durable. The code is NOT consumed in that case: the in-memory map
   * keeps the entry so a retry can succeed, and the caller must not
   * issue a token for it.
   */
  takePreAuthCode(code: string): PreAuthCodeEntry | null;
  putAccessToken(token: string, entry: StoredAccessToken): void;
  getAccessToken(token: string): StoredAccessToken | null;
  deleteAccessToken(token: string): void;
  /** Evict everything expired before `now`; returns per-map counts. */
  sweep(now: number): { preAuthCodes: number; accessTokens: number };
}

/** The original behavior, for DEMO_MODE/dev and as the fallback impl. */
export class InMemoryOfferStore implements OfferStore {
  protected preAuthCodes = new Map<string, PreAuthCodeEntry>();
  protected accessTokens = new Map<string, StoredAccessToken>();

  protected snapshot(): { preAuthCodes: [string, PreAuthCodeEntry][]; accessTokens: [string, StoredAccessToken][] } {
    return {
      preAuthCodes: [...this.preAuthCodes],
      accessTokens: [...this.accessTokens],
    };
  }

  putPreAuthCode(code: string, entry: PreAuthCodeEntry): void { this.preAuthCodes.set(code, entry); }
  takePreAuthCode(code: string): PreAuthCodeEntry | null {
    const e = this.preAuthCodes.get(code) ?? null;
    if (e) this.preAuthCodes.delete(code);
    return e;
  }
  putAccessToken(token: string, entry: StoredAccessToken): void { this.accessTokens.set(token, entry); }
  getAccessToken(token: string): StoredAccessToken | null { return this.accessTokens.get(token) ?? null; }
  deleteAccessToken(token: string): void { this.accessTokens.delete(token); }
  sweep(now: number): { preAuthCodes: number; accessTokens: number } {
    let p = 0, a = 0;
    for (const [code, e] of this.preAuthCodes) if (e.expiresAt < now) { this.preAuthCodes.delete(code); p++; }
    for (const [token, e] of this.accessTokens) if (e.expiresAt < now) { this.accessTokens.delete(token); a++; }
    return { preAuthCodes: p, accessTokens: a };
  }
}

interface ParsedStateFile {
  preAuthCodes?: unknown;
  accessTokens?: unknown;
}

function isValidEntryPair(code: unknown, entry: unknown, kind: 'preAuth' | 'token'): boolean {
  if (typeof code !== 'string' || code.length === 0) return false;
  if (typeof entry !== 'object' || entry === null) return false;
  const e = entry as Record<string, unknown>;
  if (typeof e['holderData'] !== 'object' || e['holderData'] === null) return false;
  if (typeof e['expiresAt'] !== 'number' || !Number.isFinite(e['expiresAt'])) return false;
  if (kind === 'token') {
    if (typeof e['cNonce'] !== 'string') return false;
    if (typeof e['cNonceExpiresAt'] !== 'number' || !Number.isFinite(e['cNonceExpiresAt'])) return false;
  }
  return true;
}

/**
 * File-backed store: a single JSON document in DATA_DIR, rewritten on
 * each mutation. Entries are few and short-lived (10-min codes, 5-min
 * tokens), so whole-file writes are cheap; this keeps single-instance
 * deployments restart-safe without new infrastructure.
 */
export class FileOfferStore extends InMemoryOfferStore {
  private readonly path: string;
  private readonly lockPath: string;
  private lockFd: number | undefined;
  private readonly noLock: boolean;

  constructor(dataDir: string, opts?: { noLock?: boolean }) {
    super();
    this.path = `${dataDir}/offer-state.json`;
    this.lockPath = `${dataDir}/offer-state.lock`;
    this.noLock = opts?.noLock === true; // component-test bypass, never read-only
    if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
    if (!opts?.noLock) this.acquireLock();
    this.loadFromDisk();
  }

  /** Exclusive single-writer lock; fails fast on a live second instance. */
  private acquireLock(): void {
    const fd = openSync(this.lockPath, 'a', 0o600);
    try {
      flockSync(fd, 'exnb');
      this.lockFd = fd;
    } catch (err) {
      closeSync(fd);
      throw new StorePersistenceError(`Cannot acquire exclusive offer-store writer lock at ${this.lockPath}; refusing to start.`, err);
    }
  }

  /** Test hook: release the lock without destroying state. */
  releaseLock(): void {
    if (this.lockFd === undefined) return;
    closeSync(this.lockFd);
    this.lockFd = undefined;
    // Never unlink: another writer may already have opened this inode.
  }

  /**
   * Parse and validate the complete state without writing anything.
   * On any corruption the store starts empty and the original file is
   * preserved untouched for inspection/recovery.
   */
  private loadFromDisk(): void {
    if (!existsSync(this.path)) return;
    let raw: ParsedStateFile;
    try {
      raw = JSON.parse(readFileSync(this.path, 'utf8')) as ParsedStateFile;
    } catch (err) {
      console.error('[offer-store] Could not load persisted state (starting empty, original file preserved):', (err as Error).message);
      return;
    }
    if (!Array.isArray(raw.preAuthCodes) || !Array.isArray(raw.accessTokens)) {
      console.error('[offer-store] Malformed state file (missing entry arrays; starting empty, original file preserved).');
      return;
    }
    const preAuthCodes = new Map<string, PreAuthCodeEntry>();
    for (const pair of raw.preAuthCodes) {
      if (!Array.isArray(pair) || !isValidEntryPair(pair[0], pair[1], 'preAuth')) {
        console.error('[offer-store] Malformed pre-auth entry (starting empty, original file preserved).');
        return;
      }
      preAuthCodes.set(pair[0] as string, pair[1] as PreAuthCodeEntry);
    }
    const accessTokens = new Map<string, StoredAccessToken>();
    for (const pair of raw.accessTokens) {
      if (!Array.isArray(pair) || !isValidEntryPair(pair[0], pair[1], 'token')) {
        console.error('[offer-store] Malformed access-token entry (starting empty, original file preserved).');
        return;
      }
      accessTokens.set(pair[0] as string, pair[1] as StoredAccessToken);
    }
    this.preAuthCodes = preAuthCodes;
    this.accessTokens = accessTokens;
  }

  /**
   * Crash-safe write: serialize to a temp file, then rename over the
   * live file. On success the state transition is durable; on failure
   * throw StorePersistenceError so callers do not believe a transition
   * happened.
   */
  private persist(): void {
    if (!this.noLock && this.lockFd === undefined) {
      throw new StorePersistenceError('Offer store is closed; refusing an unlocked write.');
    }
    const snapshot = this.snapshot();
    const tmp = `${this.path}.tmp.${randomUUID()}`;
    try {
      const dir = this.path.slice(0, this.path.lastIndexOf('/'));
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const fd = openSync(tmp, 'wx', 0o600);
      try {
        writeFileSync(fd, JSON.stringify(snapshot));
        fsyncSync(fd);
      } finally { closeSync(fd); }
      renameSync(tmp, this.path);
      const dirFd = openSync(dir, 'r');
      try { fsyncSync(dirFd); } finally { closeSync(dirFd); }
    } catch (err) {
      try { unlinkSync(tmp); } catch { /* nothing to clean up */ }
      throw new StorePersistenceError('offer-state persistence failed', err);
    }
  }

  putPreAuthCode(code: string, entry: PreAuthCodeEntry): void {
    super.putPreAuthCode(code, entry);
    try { this.persist(); } catch (err) { this.preAuthCodes.delete(code); throw err; }
  }

  takePreAuthCode(code: string): PreAuthCodeEntry | null {
    const entry = this.preAuthCodes.get(code) ?? null;
    if (!entry) return null;
    this.preAuthCodes.delete(code);
    try { this.persist(); }
    catch (err) {
      // Roll back: without a durable removal the code is NOT consumed.
      this.preAuthCodes.set(code, entry);
      throw err;
    }
    return entry;
  }

  putAccessToken(token: string, entry: StoredAccessToken): void {
    const prev = this.accessTokens.get(token) ?? null;
    super.putAccessToken(token, entry);
    try { this.persist(); } catch (err) {
      if (prev) this.accessTokens.set(token, prev); else this.accessTokens.delete(token);
      throw err;
    }
  }

  deleteAccessToken(token: string): void {
    if (!this.accessTokens.has(token)) return;
    const prev = this.accessTokens.get(token)!;
    this.accessTokens.delete(token);
    try { this.persist(); } catch (err) { this.accessTokens.set(token, prev); throw err; }
  }

  sweep(now: number): { preAuthCodes: number; accessTokens: number } {
    const result = super.sweep(now);
    if (result.preAuthCodes === 0 && result.accessTokens === 0) return result;
    try { this.persist(); }
    catch (err) {
      // Evictions are housekeeping: a failed eviction persist is logged,
      // never reported as durable, and never blocks the caller.
      console.error('[offer-store] Sweep eviction could not be persisted (evictions stay in memory only):', (err as Error).message);
      return { preAuthCodes: 0, accessTokens: 0 };
    }
    return result;
  }
}

/**
 * Select the store: FileOfferStore by default (restart-safe), InMemory
 * when the deployment explicitly opts out (DEMO_MODE/dev).
 */
export function createOfferStore(): OfferStore {
  const dataDir = process.env.DATA_DIR ?? '.';
  if ((process.env['OFFER_STORE'] ?? '').toLowerCase() === 'memory' || process.env.DEMO_MODE === 'true') {
    console.log('[offer-store] In-memory store (non-persistent) selected.');
    return new InMemoryOfferStore();
  }
  console.log(`[offer-store] File-backed store at ${dataDir}/offer-state.json.`);
  return new FileOfferStore(dataDir);
}
