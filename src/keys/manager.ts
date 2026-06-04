/**
 * Key Manager — generates and persists the issuer P-256 keypair.
 * Keys are stored in ./keys/issuer-key.json (not env vars — orgs need rotation).
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { generateKeyPair, exportJWK, importJWK } from 'jose';
import type { KeyLike, JWK } from 'jose';

const KEY_DIR = './keys';
const KEY_PATH = `${KEY_DIR}/issuer-key.json`;

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
  cached = { privateKey, publicKey, kid };
  return cached;
}
