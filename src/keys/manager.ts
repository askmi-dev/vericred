/**
 * Key Manager — generates and persists the issuer P-256 keypair.
 * Keys are stored in ./keys/issuer-key.json (not env vars — orgs need rotation).
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { generateKeyPair, exportJWK, importJWK } from 'jose';
import type { KeyLike, JWK } from 'jose';

const KEY_DIR = process.env.DATA_DIR ?? './keys';
const KEY_PATH = `${KEY_DIR}/issuer-key.json`;
const HISTORY_PATH = `${KEY_DIR}/key-history.json`;

interface StoredKeyPair {
  privateKey: JWK;
  publicKey: JWK;
  kid: string;
}

let cached: { privateKey: KeyLike; publicKey: KeyLike; kid: string } | null = null;

export async function getIssuerKeyPair() {
  if (cached) return cached;

  if (!existsSync(KEY_DIR)) mkdirSync(KEY_DIR, { recursive: true });

  if (existsSync(KEY_PATH)) {
    const stored = JSON.parse(readFileSync(KEY_PATH, 'utf-8')) as StoredKeyPair;
    const privateKey = await importJWK(stored.privateKey, 'ES256') as KeyLike;
    const publicKey = await importJWK(stored.publicKey, 'ES256') as KeyLike;
    cached = { privateKey, publicKey, kid: stored.kid };
    console.log(`[keys] Loaded existing issuer keypair (kid: ${stored.kid})`);
    return cached;
  }

  return rotateIssuerKeyPair();
}

/**
 * Generate a fresh P-256 keypair, archiving the current one (if any) to history.
 */
export async function rotateIssuerKeyPair() {
  if (!existsSync(KEY_DIR)) mkdirSync(KEY_DIR, { recursive: true });

  // Archive current key if it exists
  if (existsSync(KEY_PATH)) {
    const current = JSON.parse(readFileSync(KEY_PATH, 'utf-8')) as StoredKeyPair;
    const history: StoredKeyPair[] = existsSync(HISTORY_PATH) 
      ? JSON.parse(readFileSync(HISTORY_PATH, 'utf-8')) 
      : [];
    history.push(current);
    writeFileSync(HISTORY_PATH, JSON.stringify(history, null, 2));
    console.log(`[keys] Archived key ${current.kid} to history.`);
  }

  console.log('[keys] Generating new P-256 issuer keypair...');
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const kid = crypto.randomUUID();
  const stored: StoredKeyPair = {
    privateKey: await exportJWK(privateKey),
    publicKey: await exportJWK(publicKey),
    kid,
  };
  writeFileSync(KEY_PATH, JSON.stringify(stored, null, 2));
  console.log(`[keys] Keypair generated and saved (kid: ${kid})`);
  cached = { 
    privateKey: await importJWK(stored.privateKey, 'ES256') as KeyLike, 
    publicKey: await importJWK(stored.publicKey, 'ES256') as KeyLike, 
    kid 
  };
  return cached;
}

/**
 * Returns all public keys (current + history) for DID document generation.
 */
export async function getAllPublicKeys(): Promise<Array<{ publicKey: JWK; kid: string }>> {
  const keys: Array<{ publicKey: JWK; kid: string }> = [];
  
  if (existsSync(KEY_PATH)) {
    const current = JSON.parse(readFileSync(KEY_PATH, 'utf-8')) as StoredKeyPair;
    keys.push({ publicKey: current.publicKey, kid: current.kid });
  }

  if (existsSync(HISTORY_PATH)) {
    const history = JSON.parse(readFileSync(HISTORY_PATH, 'utf-8')) as StoredKeyPair[];
    for (const h of history) {
      keys.push({ publicKey: h.publicKey, kid: h.kid });
    }
  }

  return keys;
}
