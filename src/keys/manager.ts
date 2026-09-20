import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, importJWK, type KeyLike, type JWK } from 'jose';
import { atomicWrite } from '../storage/atomic.js';
import { audit } from '../storage/audit.js';
interface Stored { publicKey: JWK; privateKey: JWK; kid: string; }
interface PublicKey { publicKey: JWK; kid: string; }
interface Active { publicKey: KeyLike; privateKey: KeyLike; kid: string; }
const cached = new Map<string, Active>();
const rotations = new Map<string, Promise<Active>>();
const paths = () => {
  const dir = process.env.DATA_DIR ?? './keys';
  return { key: join(dir, 'issuer-key.json'), history: join(dir, 'key-history.json') };
};
async function importStored(stored: Stored): Promise<Active> {
  return { kid: stored.kid, privateKey: await importJWK(stored.privateKey, 'ES256') as KeyLike, publicKey: await importJWK(stored.publicKey, 'ES256') as KeyLike };
}
export async function getIssuerKeyPair(): Promise<Active> {
  const p = paths();
  if (rotations.has(p.key)) return rotations.get(p.key)!;
  const existing = cached.get(p.key);
  if (existing) return existing;
  if (!existsSync(p.key)) return rotateIssuerKeyPair();
  const result = await importStored(JSON.parse(readFileSync(p.key, 'utf8')));
  cached.set(p.key, result);
  return result;
}
export async function rotateIssuerKeyPair(actor = 'system'): Promise<Active> {
  const p = paths();
  if (rotations.has(p.key)) return rotations.get(p.key)!;
  const operation = (async () => {
    const pair = await generateKeyPair('ES256', { extractable: true });
    const stored: Stored = { kid: randomUUID(), privateKey: await exportJWK(pair.privateKey), publicKey: await exportJWK(pair.publicKey) };
    const history: PublicKey[] = existsSync(p.history) ? JSON.parse(readFileSync(p.history, 'utf8')).map((k: PublicKey) => ({ kid: k.kid, publicKey: k.publicKey })) : [];
    if (existsSync(p.key)) {
      const old: Stored = JSON.parse(readFileSync(p.key, 'utf8'));
      if (!history.some(k => k.kid === old.kid)) history.push({ kid: old.kid, publicKey: old.publicKey });
    }
    audit('key.rotation.requested', actor, stored.kid);
    atomicWrite(p.history, JSON.stringify(history));
    atomicWrite(p.key, JSON.stringify(stored));
    const result = await importStored(stored);
    cached.set(p.key, result);
    audit('key.rotated', actor, stored.kid);
    return result;
  })();
  rotations.set(p.key, operation);
  try { return await operation; } finally { rotations.delete(p.key); }
}
export async function getAllPublicKeys(): Promise<PublicKey[]> {
  const p = paths();
  const keys: PublicKey[] = [];
  for (const file of [p.key, p.history]) {
    if (!existsSync(file)) continue;
    const data = JSON.parse(readFileSync(file, 'utf8'));
    for (const k of Array.isArray(data) ? data : [data]) {
      if (!keys.some(existing => existing.kid === k.kid)) keys.push({ kid: k.kid, publicKey: k.publicKey });
    }
  }
  return keys;
}
