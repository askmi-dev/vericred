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
 * Security note: access tokens are bearer credentials and are stored in
 * DATA_DIR. That directory already holds issuer keys and admin secrets
 * and must be treated as private infrastructure state; deployments with
 * stricter needs can implement the interface against Redis/pg (see
 * issue #31) via `createOfferStore` selection.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';

export interface PreAuthCodeEntry {
  holderData: Record<string, unknown>;
  expiresAt: number;
  credentialType?: string;
  claims?: Record<string, unknown>;
}

export interface StoredAccessToken {
  holderData: Record<string, unknown>;
  expiresAt: number;
  cNonce: string;
  cNonceExpiresAt: number;
  credentialType?: string;
  claims?: Record<string, unknown>;
}

export interface OfferStore {
  putPreAuthCode(code: string, entry: PreAuthCodeEntry): void;
  /** Get + delete atomically: pre-auth codes are single-use. */
  takePreAuthCode(code: string): PreAuthCodeEntry | null;
  putAccessToken(token: string, entry: StoredAccessToken): void;
  getAccessToken(token: string): StoredAccessToken | null;
  deleteAccessToken(token: string): void;
  /** Evict everything expired before `now`; returns per-map counts. */
  sweep(now: number): { preAuthCodes: number; accessTokens: number };
}

/** The original behavior, for DEMO_MODE/dev and as the fallback impl. */
export class InMemoryOfferStore implements OfferStore {
  private preAuthCodes = new Map<string, PreAuthCodeEntry>();
  private accessTokens = new Map<string, StoredAccessToken>();
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

/**
 * File-backed store: a single JSON document in DATA_DIR, rewritten on
 * each mutation. Entries are few and short-lived (10-min codes, 5-min
 * tokens), so whole-file writes are cheap; this keeps single-instance
 * deployments restart-safe without new infrastructure.
 */
export class FileOfferStore extends InMemoryOfferStore {
  private readonly path: string;

  constructor(dataDir: string) {
    super();
    this.path = `${dataDir}/offer-state.json`;
    try {
      if (existsSync(this.path)) {
        const raw = JSON.parse(readFileSync(this.path, 'utf8')) as {
          preAuthCodes?: [string, PreAuthCodeEntry][];
          accessTokens?: [string, StoredAccessToken][];
        };
        for (const [code, entry] of raw.preAuthCodes ?? []) this.putPreAuthCode(code, entry);
        for (const [token, entry] of raw.accessTokens ?? []) this.putAccessToken(token, entry);
      }
    } catch (err) {
      // Corrupt state must not brick the gateway: start empty and log.
      console.error('[offer-store] Could not load persisted state (starting empty):', (err as Error).message);
    }
  }

  private persist(): void {
    try {
      const dir = this.path.slice(0, this.path.lastIndexOf('/'));
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(this.path, JSON.stringify({
        preAuthCodes: [...(this as unknown as { preAuthCodes: Map<string, PreAuthCodeEntry> }).preAuthCodes],
        accessTokens: [...(this as unknown as { accessTokens: Map<string, StoredAccessToken> }).accessTokens],
      }), 'utf8');
    } catch (err) {
      console.error('[offer-store] Could not persist offer state:', (err as Error).message);
    }
  }

  putPreAuthCode(code: string, entry: PreAuthCodeEntry): void { super.putPreAuthCode(code, entry); this.persist(); }
  takePreAuthCode(code: string): PreAuthCodeEntry | null { const e = super.takePreAuthCode(code); if (e) this.persist(); return e; }
  putAccessToken(token: string, entry: StoredAccessToken): void { super.putAccessToken(token, entry); this.persist(); }
  deleteAccessToken(token: string): void { super.deleteAccessToken(token); this.persist(); }
  sweep(now: number): { preAuthCodes: number; accessTokens: number } {
    const result = super.sweep(now);
    if (result.preAuthCodes > 0 || result.accessTokens > 0) this.persist();
    return result;
  }
}

/**
 * Select the store: FileOfferStore by default (restart-safe), InMemory
 * when the deployment explicitly opts out (DEMO_MODE/dev).
 */
export function createOfferStore(): OfferStore {
  const dataDir = process.env.DATA_DIR ?? '.';
  if ((process.env['OFFER_STORE'] ?? '').toLowerCase() === 'memory' || process.env['DEMO_MODE'] === 'true') {
    console.log('[offer-store] In-memory store (non-persistent) selected.');
    return new InMemoryOfferStore();
  }
  console.log(`[offer-store] File-backed store at ${dataDir}/offer-state.json.`);
  return new FileOfferStore(dataDir);
}
