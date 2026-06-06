/**
 * StatusList2021 manager.
 * - Maintains a bitstring of revoked credential indices (stored in data/statuslist.json)
 * - Serves a signed StatusList2021 credential at /status/{listId}
 * - Each issued credential gets an index; revocation flips the bit
 *
 * Spec: https://www.w3.org/TR/vc-status-list/
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomUUID } from 'crypto';
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

interface StatusListStore {
  listId: string;
  nextIndex: number;
  revokedIndices: number[];
  issuedCredentials: Array<{
    credentialId: string;
    holderEmail: string;
    statusIndex: number;
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
    nextIndex: 0,
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

/** Assign a status list index to a new credential. Returns { listId, statusIndex }. */
export function assignStatusIndex(credentialId: string, holderEmail: string): { listId: string; statusIndex: number } {
  const store = loadStore();
  if (store.nextIndex >= LIST_SIZE) throw new Error('StatusList full — create a new list');

  const statusIndex = store.nextIndex++;
  store.issuedCredentials.push({
    credentialId,
    holderEmail,
    statusIndex,
    issuedAt: new Date().toISOString(),
    revoked: false,
  });
  saveStore(store);
  return { listId: store.listId, statusIndex };
}

/** Revoke a credential by ID. Returns true if found and revoked. */
export function revokeCredential(credentialId: string, reason: string = 'Administrative Revocation'): boolean {
  const store = loadStore();
  const entry = store.issuedCredentials.find(c => c.credentialId === credentialId);
  if (!entry || entry.revoked) return false;

  const revokedAt = new Date().toISOString();
  entry.revoked = true;
  entry.revokedAt = revokedAt;
  store.revokedIndices.push(entry.statusIndex);
  saveStore(store);

  // Audit logging (simulated as console log, could be a separate file/DB)
  console.log(`[audit] REVOKE: Credential ${credentialId} (Index ${entry.statusIndex}) revoked at ${revokedAt}. Reason: ${reason}`);

  return true;
}

/** Get all issued credentials for admin view. */
export function getIssuedCredentials() {
  return loadStore().issuedCredentials;
}

/** Get the current list ID. */
export function getListId(): string {
  return loadStore().listId;
}

/** Build and sign a StatusList2021 VC. Served at /status/{listId}. */
export async function buildStatusListJWT(): Promise<string> {
  const store = loadStore();
  const { privateKey, kid } = await getIssuerKeyPair();
  const config = loadConfig();

  const bitstring = buildBitstring(store.revokedIndices);
  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: config.issuer.did,
    issuedAt: new Date().toISOString(),
    credentialSubject: {
      id: `${config.issuer.url}/status/${store.listId}`,
      type: 'StatusList2021',
      statusPurpose: 'revocation',
      encodedList: bitstring,
    },
  })
    .setProtectedHeader({ alg: 'ES256', kid, typ: 'JWT' })
    .setIssuedAt(now)
    .sign(privateKey);
}
