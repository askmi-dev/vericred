import { existsSync, readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { gzipSync, deflateSync } from 'node:zlib';
import { certificateSigner } from '../wallet/profile.js';
import { SignJWT } from 'jose';
import { getIssuerKeyPair } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';
import { atomicWrite } from '../storage/atomic.js';
import { audit } from '../storage/audit.js';
const path = () => (process.env.DATA_DIR ?? './data') + '/statuslist.json';
export const LIST_SIZE = 131072;
interface Issued {
  credentialId: string; holderEmail: string; listId: string; statusIndex: number;
  issuedAt: string; revoked: boolean; revokedAt?: string; credentialType?: string; expiresAt?: string;
}
interface Store { retiredListIds?: string[]; listId: string; listIds: string[]; nextIndex: number; issuedCredentials: Issued[]; }
function loadStore(): Store {
  if (!existsSync(path())) return { listId: randomUUID(), listIds: [], nextIndex: 0, issuedCredentials: [] };
  const store = JSON.parse(readFileSync(path(), 'utf8')) as Store;
  store.listIds ??= [store.listId];
  for (const entry of store.issuedCredentials) entry.listId ??= store.listId;
  return store;
}
function save(store: Store) { atomicWrite(path(), JSON.stringify(store)); }
export function assignStatusIndex(credentialId: string, holderEmail: string, credentialType?: string, expiresAt?: string) {
  const store = loadStore();
  if (store.retiredListIds?.includes(store.listId) || store.nextIndex >= LIST_SIZE) { store.listId = randomUUID(); store.nextIndex = 0; }
  if (!store.listIds.includes(store.listId)) store.listIds.push(store.listId);
  const statusIndex = store.nextIndex++;
  store.issuedCredentials.push({ credentialId, holderEmail, credentialType, expiresAt, listId: store.listId, statusIndex, issuedAt: new Date().toISOString(), revoked: false });
  audit('credential.allocated', 'issuer', credentialId);
  save(store);
  return { listId: store.listId, statusIndex };
}
export function revokeCredential(credentialId: string, reason = 'Administrative revocation', actor = 'admin') {
  const store = loadStore();
  const entry = store.issuedCredentials.find(c => c.credentialId === credentialId);
  if (!entry || entry.revoked) return false;
  entry.revoked = true; entry.revokedAt = new Date().toISOString();
  audit('credential.revoke', actor, credentialId, { reason });
  save(store);
  return true;
}
export function getIssuedCredentials() { return loadStore().issuedCredentials; }
export function getListId() {
  const store = loadStore();
  if (!store.listIds.includes(store.listId)) { store.listIds.push(store.listId); save(store); }
  return store.listId;
}
export function isRetiredList(id: string) { return loadStore().retiredListIds?.includes(id) ?? false; }
export function hasList(id: string) { const store = loadStore(); return store.listIds.includes(id); }
export async function buildStatusListJWT(listId = getListId()) {
  const store = loadStore();
  if (!store.listIds.includes(listId)) throw new Error('Unknown status list');
  const bytes = Buffer.alloc(LIST_SIZE / 8, store.retiredListIds?.includes(listId) ? 255 : 0);
  for (const entry of store.issuedCredentials) {
    if (entry.listId === listId && entry.revoked) bytes[Math.floor(entry.statusIndex / 8)] |= 1 << (7 - (entry.statusIndex % 8));
  }
  const config = loadConfig();
  const url = config.issuer.url + '/status/' + listId;
  const { privateKey, kid } = await getIssuerKeyPair();
  return new SignJWT({
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/vc/status-list/2021/v1'],
    id: url, type: ['VerifiableCredential', 'StatusList2021Credential'],
    issuer: config.issuer.did, issuanceDate: new Date().toISOString(),
    credentialSubject: { id: url + '#list', type: 'StatusList2021', statusPurpose: 'revocation', encodedList: gzipSync(bytes).toString('base64url') },
  }).setIssuer(config.issuer.did).setProtectedHeader({ alg: 'ES256', kid, typ: 'JWT' }).setIssuedAt().sign(privateKey);
}

/** Token Status List: one-bit entries, LSB-first, zlib (not GZIP). */
export async function buildTokenStatusListJWT(listId: string) {
  const store = loadStore();
  if (!store.listIds.includes(listId)) throw new Error('Unknown status list');
  const bytes = Buffer.alloc(LIST_SIZE / 8, store.retiredListIds?.includes(listId) ? 255 : 0);
  for (const entry of store.issuedCredentials) {
    if (entry.listId === listId && entry.revoked) bytes[Math.floor(entry.statusIndex / 8)] |= 1 << (entry.statusIndex % 8);
  }
  const config = loadConfig();
  const signer = await certificateSigner('issuer');
  const url = config.issuer.url + '/status/token/' + listId;
  return new SignJWT({ status_list: { bits: 1, lst: deflateSync(bytes).toString('base64url') }, ttl: 60 })
    .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt', x5c: signer.x5c })
    .setIssuer(config.issuer.url).setSubject(url).setIssuedAt().setExpirationTime('5m').sign(signer.privateKey);
}
