import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { compactDecrypt, CompactEncrypt, exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { atomicWrite } from '../storage/atomic.js';

export const encryptionAlgorithm = 'ECDH-ES';
export const encryptionMethods = ['A128GCM', 'A256GCM'];
const loading = new Map<string, Promise<{ publicKey: JWK; privateKey: JWK }>>();
export async function newEncryptionKey() {
  const pair = await generateKeyPair(encryptionAlgorithm, { crv: 'P-256', extractable: true });
  const kid = randomUUID();
  return { publicKey: { ...await exportJWK(pair.publicKey), kid, alg: encryptionAlgorithm, use: 'enc' },
    privateKey: { ...await exportJWK(pair.privateKey), kid, alg: encryptionAlgorithm, use: 'enc' } };
}
export async function issuerEncryptionKey() {
  const path = join(process.env.DATA_DIR ?? './data', 'credential-encryption-key.json');
  if (existsSync(path)) return JSON.parse(readFileSync(path, 'utf8')) as Awaited<ReturnType<typeof newEncryptionKey>>;
  if (loading.has(path)) return loading.get(path)!;
  const operation = newEncryptionKey().then(pair => { atomicWrite(path, JSON.stringify(pair)); return pair; });
  loading.set(path, operation);
  try { return await operation; } finally { loading.delete(path); }
}
export async function decryptMessage(token: unknown, privateKey: JWK): Promise<Record<string, unknown>> {
  if (typeof token !== 'string' || token.length > 128_000) throw new Error('Invalid encrypted message');
  const { plaintext, protectedHeader } = await compactDecrypt(token, await importJWK(privateKey, encryptionAlgorithm), {
    keyManagementAlgorithms: [encryptionAlgorithm], contentEncryptionAlgorithms: encryptionMethods,
  });
  if (protectedHeader.kid !== privateKey.kid || protectedHeader.zip !== undefined) throw new Error('Invalid encryption header');
  const body: unknown = JSON.parse(Buffer.from(plaintext).toString('utf8'));
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Invalid encrypted payload');
  return body as Record<string, unknown>;
}
export async function responseEncryption(value: unknown) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Response encryption required');
  const { jwk, enc, ...extra } = value as { jwk?: JWK; enc?: string; [key: string]: unknown };
  if (Object.keys(extra).length || !jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d ||
      jwk.alg !== encryptionAlgorithm || (jwk.use !== undefined && jwk.use !== 'enc') || !enc || !encryptionMethods.includes(enc)) throw new Error('Unsupported response encryption');
  const key = await importJWK({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, encryptionAlgorithm);
  return async (body: Record<string, unknown>) => new CompactEncrypt(Buffer.from(JSON.stringify(body)))
    .setProtectedHeader({ alg: encryptionAlgorithm, enc, ...(jwk.kid ? { kid: jwk.kid } : {}) }).encrypt(key);
}
