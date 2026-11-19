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
 *
 * Legacy migration: credentials issued before the switch reference a W3C
 * StatusList2021 at /status/{oldListId}. Serving the new format at that URL
 * would let a lenient verifier read "no revocation bit" as "valid" -- a
 * revoked credential would be accepted again. So an existing store keeps its
 * old list ID as `legacyListId`, still served as StatusList2021 (revocations
 * included), and new credentials go to a fresh Token Status List ID.
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

// Cache for the signed Token Status List to avoid re-signing on every request
let cachedStatusListJWT: { jwt: string; revokedIndicesHash: string; timestamp: number } | null = null;
const STATUSLIST_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes cache TTL
/** Seconds verifiers may cache the list before fetching again (Token Status List `ttl`). */
const STATUSLIST_TTL_S = 300;
/** Lifetime of one signed Status List Token. */
const STATUSLIST_EXP_S = 24 * 3600;

const TOKEN_STATUS_LIST = 'token-status-list';
/** Operator-set marker: migrate this store as a pre-Token-Status-List StatusList2021 store. */
const STATUSLIST2021 = 'statuslist2021';

// A type alias (not an interface) so records stay assignable to
// Record<string, unknown>, which the admin masking helpers take.
type IssuedCredentialRecord = {
  credentialId: string;
  holderEmail: string;
  statusIndex: number;
  /** List this credential's index lives in. Absent = legacy StatusList2021 list. */
  listId?: string;
  /** Copies issued together in one batch; revoked together. */
  batchId?: string;
  issuedAt: string;
  revoked: boolean;
  revokedAt?: string;
};

interface StatusListStore {
  /** Current list: IETF Token Status List, used for all new credentials. */
  listId: string;
  /**
   * Marks a store that has been migrated to (or created as) a Token Status
   * List. An operator may set "statuslist2021" to force legacy migration.
   */
  format?: typeof TOKEN_STATUS_LIST | typeof STATUSLIST2021;
  /** Pre-migration list, still served as StatusList2021 for credentials issued before. */
  legacyListId?: string;
  /** Legacy sequential counter from before random indices; no longer used. */
  nextIndex?: number;
  /** Legacy field; revocation state is derived from issuedCredentials. */
  revokedIndices?: number[];
  issuedCredentials: IssuedCredentialRecord[];
}

function loadStore(): StatusListStore {
  const { dataDir, statusPath } = getPaths();
  if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true });
  if (existsSync(statusPath)) {
    const store = JSON.parse(readFileSync(statusPath, 'utf-8')) as StatusListStore;
    if (store.format !== TOKEN_STATUS_LIST) {
      migrateLegacyStore(store);
      saveStore(store);
    }
    return store;
  }
  const store: StatusListStore = {
    listId: randomUUID(),
    format: TOKEN_STATUS_LIST,
    issuedCredentials: [],
  };
  writeFileSync(statusPath, JSON.stringify(store, null, 2));
  return store;
}

/**
 * Move a pre-Token-Status-List store onto a fresh list ID. Credentials that
 * were already issued keep pointing at the old ID, which stays StatusList2021.
 */
function migrateLegacyStore(store: StatusListStore): void {
  // Classify only on positive evidence. Every StatusList2021 version of this
  // module created its store with a sequential `nextIndex` counter; an operator
  // can also force it with format "statuslist2021". Guessing wrong in either
  // direction serves a credential's status in a format it wasn't issued
  // against, which a lenient verifier may read as "not revoked". So an
  // unclassifiable store with credentials is refused (fail-closed) until an
  // operator marks it.
  const isLegacy = store.format === STATUSLIST2021 || store.nextIndex !== undefined;
  if (!isLegacy && store.issuedCredentials.length > 0) {
    throw new Error(
      '[statuslist] Cannot tell which revocation format data/statuslist.json was issued with. '
      + 'Add "format": "token-status-list" if it was created by the Token Status List version, '
      + 'or "format": "statuslist2021" if its credentials reference a W3C StatusList2021. '
      + 'Refusing to serve status or issue until set.',
    );
  }
  store.format = TOKEN_STATUS_LIST;
  if (!isLegacy || store.issuedCredentials.length === 0) return; // nothing references an old URL
  store.legacyListId = store.listId;
  store.listId = randomUUID();
  console.log(`[statuslist] Migrated to Token Status List ${store.listId}; `
    + `legacy StatusList2021 ${store.legacyListId} kept for ${store.issuedCredentials.length} existing credential(s)`);
}

function saveStore(store: StatusListStore): void {
  const { statusPath } = getPaths();
  writeFileSync(statusPath, JSON.stringify(store, null, 2));
}

/**
 * The list a record belongs to. Records without listId predate it: they sit in
 * the legacy list if the store was migrated, otherwise in the current list.
 */
function listOf(store: StatusListStore, c: IssuedCredentialRecord): string {
  return c.listId ?? store.legacyListId ?? store.listId;
}

function revokedIndicesIn(store: StatusListStore, listId: string): number[] {
  return store.issuedCredentials
    .filter(c => c.revoked && listOf(store, c) === listId)
    .map(c => c.statusIndex)
    .sort((a, b) => a - b);
}

function buildBitstring(revokedIndices: number[]): Uint8Array {
  const bytes = new Uint8Array(Math.ceil(LIST_SIZE / 8));
  for (const idx of revokedIndices) {
    const byteIndex = Math.floor(idx / 8);
    const bitIndex = idx % 8;
    bytes[byteIndex] |= (1 << bitIndex);
  }
  return bytes;
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
  const used = new Set(
    store.issuedCredentials.filter(c => listOf(store, c) === store.listId).map(c => c.statusIndex),
  );
  const statusIndex = pickRandomFreeIndex(used);
  store.issuedCredentials.push({
    credentialId,
    holderEmail,
    statusIndex,
    listId: store.listId,
    ...(batchId ? { batchId } : {}),
    issuedAt: new Date().toISOString(),
    revoked: false,
  });
  saveStore(store);
  return { listId: store.listId, statusIndex };
}

/**
 * Revoke a credential by ID, together with every other copy from its batch.
 * Works for legacy (StatusList2021) credentials too. Returns true if found and revoked.
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
export function searchCredentials(query: string): IssuedCredentialRecord[] {
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

/** Get the current (Token Status List) list ID. */
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
  const revoked = revokedIndicesIn(store, store.listId);
  const revokedIndicesHash = store.listId + ':' + revoked.join(',');

  // Check cache validity
  if (cachedStatusListJWT &&
      cachedStatusListJWT.revokedIndicesHash === revokedIndicesHash &&
      Date.now() - cachedStatusListJWT.timestamp < STATUSLIST_CACHE_TTL_MS) {
    return cachedStatusListJWT.jwt;
  }

  const jwt = await new SignJWT({
    iss: config.issuer.did,
    sub: `${config.issuer.url}/status/${store.listId}`,
    iat: now,
    exp: now + STATUSLIST_EXP_S,
    ttl: STATUSLIST_TTL_S,
    status_list: {
      bits: 1,
      lst: deflateSync(buildBitstring(revoked)).toString('base64url'),
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

/**
 * Build the legacy W3C StatusList2021 credential for credentials issued
 * before the Token Status List switch. Same shape those credentials were
 * issued against, so their verifiers keep seeing revocations.
 *
 * Known deviation, kept on purpose: the original implementation set bits
 * LSB-first and did not GZIP `encodedList`, unlike the W3C spec (MSB-first,
 * GZIP). This reproduces it byte-for-byte, because existing verifiers were
 * built against it. A strictly spec-conformant verifier fails to gunzip and
 * rejects (fail-closed). The list retires once legacy credentials expire.
 */
async function buildLegacyStatusList2021JWT(store: StatusListStore, legacyListId: string): Promise<string> {
  const { privateKey, kid } = await getIssuerKeyPair();
  const config = loadConfig();
  const bitstring = Buffer.from(buildBitstring(revokedIndicesIn(store, legacyListId))).toString('base64url');

  return new SignJWT({
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: config.issuer.did,
    issuedAt: new Date().toISOString(),
    credentialSubject: {
      id: `${config.issuer.url}/status/${legacyListId}`,
      type: 'StatusList2021',
      statusPurpose: 'revocation',
      encodedList: bitstring,
    },
  })
    .setProtectedHeader({ alg: 'ES256', kid, typ: 'JWT' })
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .sign(privateKey);
}

/**
 * Resolve /status/{listId}: the current Token Status List, the legacy
 * StatusList2021 for credentials issued before migration, or null (404).
 */
export async function getStatusListResponse(
  listId: string,
): Promise<{ contentType: string; body: string } | null> {
  const store = loadStore();
  if (listId === store.listId) {
    return { contentType: 'application/statuslist+jwt', body: await buildStatusListJWT() };
  }
  if (store.legacyListId && listId === store.legacyListId) {
    return { contentType: 'application/jwt', body: await buildLegacyStatusList2021JWT(store, listId) };
  }
  return null;
}
