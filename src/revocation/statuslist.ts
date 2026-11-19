/**
 * Token Status List manager (IETF draft-ietf-oauth-status-list).
 * - Maintains a 1-bit list of revoked credential indices (stored in data/statuslist.json)
 * - Serves a signed Status List Token (typ "statuslist+jwt") at /status/{listId}
 * - Each issued credential gets a RANDOM unused index, so the index reveals
 *   nothing about issuance order and can't be used to link batch copies
 * - Copies issued together share a batchId (issuer-side only, never in the
 *   credential); revoking one copy revokes the whole batch
 * - Auto-refresh: re-signs and re-publishes the list on any revocation
 *
 * The German EUDI ecosystem requires Token Status Lists for SD-JWT VC.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomInt, randomUUID } from 'crypto';
import { deflateSync } from 'zlib';
import { SignJWT } from 'jose';
import { getIssuerKeyPair } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';

function getPaths() {
  const dataDir = process.env.DATA_DIR ?? './data';
  return {
    dataDir,
    statusPath: `${dataDir}/statuslist.json`,
  };
}
const LIST_SIZE = 131072; // 16KB bitstring = 131072 credential slots

// Cache for the signed StatusList JWT to avoid re-signing on every request
let cachedStatusListJWT: { jwt: string; revokedIndicesHash: string; timestamp: number } | null = null;
const STATUSLIST_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes cache TTL
/** Seconds verifiers may cache the list before fetching again (Token Status List `ttl`). */
const STATUSLIST_TTL_S = 300;
/** Lifetime of one signed Status List Token. */
const STATUSLIST_EXP_S = 24 * 3600;

interface StatusListStore {
  listId: string;
  /** Legacy sequential counter from before random indices; no longer used. */
  nextIndex?: number;
  revokedIndices: number[];
  issuedCredentials: Array<{
    credentialId: string;
    holderEmail: string;
    statusIndex: number;
    /** Copies issued together in one batch; revoked together. */
    batchId?: string;
    issuedAt: string;
    revoked: boolean;
    revokedAt?: string;
  }>;
}

function loadStore(): StatusListStore {
  const { dataDir, statusPath } = getPaths();
  if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
  if (existsSync(statusPath)) {
    return JSON.parse(readFileSync(statusPath, 'utf-8')) as StatusListStore;
  }
  const store: StatusListStore = {
    listId: randomUUID(),
    revokedIndices: [],
    issuedCredentials: [],
  };
  writeFileSync(statusPath, JSON.stringify(store, null, 2));
  return store;
}

function saveStore(store: StatusListStore): void {
  const { statusPath } = getPaths();
  writeFileSync(statusPath, JSON.stringify(store, null, 2));
}

function buildBitstring(revokedIndices: number[]): string {
  const bytes = new Uint8Array(Math.ceil(LIST_SIZE / 8));
  for (const idx of revokedIndices) {
    const byteIndex = Math.floor(idx / 8);
    const bitIndex = idx % 8;
    bytes[byteIndex] |= (1 << bitIndex);
  }
  return Buffer.from(bytes).toString('base64url');
}

/** Pick a uniformly random index not yet used in this list. */
function pickRandomFreeIndex(used: Set<number>): number {
  if (used.size >= LIST_SIZE) throw new Error('StatusList full — create a new list');
  // Random probing is fast while the list is mostly free; fall back to a
  // scan from a random start so a nearly full list still terminates.
  for (let attempt = 0; attempt < 64; attempt++) {
    const idx = randomInt(LIST_SIZE);
    if (!used.has(idx)) return idx;
  }
  const start = randomInt(LIST_SIZE);
  for (let i = 0; i < LIST_SIZE; i++) {
    const idx = (start + i) % LIST_SIZE;
    if (!used.has(idx)) return idx;
  }
  throw new Error('StatusList full — create a new list');
}

/**
 * Assign a random status list index to a new credential. Returns { listId, statusIndex }.
 * Pass the same batchId for copies issued together so they are revoked together.
 */
export function assignStatusIndex(
  credentialId: string,
  holderEmail: string,
  batchId?: string,
): { listId: string; statusIndex: number } {
  const store = loadStore();
  const used = new Set(store.issuedCredentials.map(c => c.statusIndex));
  const statusIndex = pickRandomFreeIndex(used);
  store.issuedCredentials.push({
    credentialId,
    holderEmail,
    statusIndex,
    ...(batchId ? { batchId } : {}),
    issuedAt: new Date().toISOString(),
    revoked: false,
  });
  saveStore(store);
  return { listId: store.listId, statusIndex };
}

/**
 * Revoke a credential by ID, together with every other copy from its batch.
 * Returns true if found and revoked.
 */
export function revokeCredential(credentialId: string, reason: string = 'Administrative Revocation'): boolean {
  const store = loadStore();
  const entry = store.issuedCredentials.find(c => c.credentialId === credentialId);
  if (!entry || entry.revoked) return false;

  const revokedAt = new Date().toISOString();
  const targets = entry.batchId
    ? store.issuedCredentials.filter(c => c.batchId === entry.batchId && !c.revoked)
    : [entry];

  for (const t of targets) {
    t.revoked = true;
    t.revokedAt = revokedAt;
    if (!store.revokedIndices.includes(t.statusIndex)) {
      store.revokedIndices.push(t.statusIndex);
    }
  }
  saveStore(store);

  // Invalidate cache to force re-signing on next request
  cachedStatusListJWT = null;

  // Audit logging (simulated as console log, could be a separate file/DB)
  console.log(`[audit] REVOKE: Credential ${credentialId} (${targets.length} cop${targets.length === 1 ? 'y' : 'ies'}) revoked at ${revokedAt}. Reason: ${reason}`);

  return true;
}

/** Get all issued credentials for admin view. */
export function getIssuedCredentials() {
  return loadStore().issuedCredentials;
}

/** Search issued credentials by various criteria. */
export function searchCredentials(query: string): StatusListStore['issuedCredentials'] {
  const store = loadStore();
  const q = query.toLowerCase().trim();
  
  if (!q) {
    return store.issuedCredentials;
  }

  return store.issuedCredentials.filter(cred => {
    // Search by credential ID
    if (cred.credentialId.toLowerCase().includes(q)) return true;
    
    // Search by holder email
    if (cred.holderEmail.toLowerCase().includes(q)) return true;
    
    // Search by status
    if (cred.revoked && q.includes('revoked')) return true;
    if (!cred.revoked && q.includes('active')) return true;
    
    // Search by date (issuedAt)
    if (cred.issuedAt && cred.issuedAt.toLowerCase().includes(q)) return true;
    
    // Search by revokedAt
    if (cred.revokedAt && cred.revokedAt.toLowerCase().includes(q)) return true;
    
    return false;
  });
}

/** Get credential by ID. */
export function getCredentialById(credentialId: string) {
  const store = loadStore();
  return store.issuedCredentials.find(c => c.credentialId === credentialId);
}

/** Get the current list ID. */
export function getListId(): string {
  return loadStore().listId;
}

/**
 * Build and sign a Status List Token (draft-ietf-oauth-status-list).
 * Served at /status/{listId}. `lst` is the ZLIB-compressed 1-bit list,
 * index 0 in the least significant bit of byte 0; 1 = INVALID (revoked).
 */
export async function buildStatusListJWT(): Promise<string> {
  const store = loadStore();
  const { privateKey, kid } = await getIssuerKeyPair();
  const config = loadConfig();

  const now = Math.floor(Date.now() / 1000);

  const revokedIndicesHash = store.revokedIndices.sort((a, b) => a - b).join(',');
  
  // Check cache validity
  if (cachedStatusListJWT && 
      cachedStatusListJWT.revokedIndicesHash === revokedIndicesHash &&
      Date.now() - cachedStatusListJWT.timestamp < STATUSLIST_CACHE_TTL_MS) {
    return cachedStatusListJWT.jwt;
  }

  const bitstring = Buffer.from(buildBitstring(store.revokedIndices), 'base64url');
  const jwt = await new SignJWT({
    iss: config.issuer.did,
    sub: `${config.issuer.url}/status/${store.listId}`,
    iat: now,
    exp: now + STATUSLIST_EXP_S,
    ttl: STATUSLIST_TTL_S,
    status_list: {
      bits: 1,
      lst: deflateSync(bitstring).toString('base64url'),
    },
  })
    .setProtectedHeader({ alg: 'ES256', kid, typ: 'statuslist+jwt' })
    .sign(privateKey);

  // Cache the signed JWT
  cachedStatusListJWT = {
    jwt,
    revokedIndicesHash,
    timestamp: Date.now()
  };

  return jwt;
}
