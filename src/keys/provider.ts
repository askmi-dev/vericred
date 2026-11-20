/**
 * Issuer key provider — the seam between VeriCred and wherever the issuer key lives.
 *
 * Call sites never touch a private key. They ask the provider to sign a JWT, so a
 * KMS/HSM adapter (AWS KMS, PKCS#11, Azure Key Vault, ...) can keep the key
 * non-exportable. The default provider is the file-based key manager (`./manager.ts`)
 * and behaves exactly as before.
 *
 * Selection: `KEY_PROVIDER` (default `file`). Any other value fails closed at first use
 * unless an adapter was registered with `setKeyProvider()`.
 */
import { base64url } from 'jose';
import type { JWK, JWTPayload } from 'jose';
import { fileKeyProvider } from './manager.js';

export interface ActiveIssuerKey {
  kid: string;
  publicKey: JWK;
}

export interface IssuerKeyProvider {
  /** kid and public JWK of the key that signs new credentials. */
  getActiveKey(): Promise<ActiveIssuerKey>;
  /** Public keys of the active key and all archived keys, for the DID document. */
  getAllPublicKeys(): Promise<Array<{ publicKey: JWK; kid: string }>>;
  /**
   * Sign a JWT with the active key (ES256). The provider sets `alg` and `kid` in the
   * protected header; the caller supplies `typ` and the claims.
   */
  signJwt(payload: JWTPayload, typ: string): Promise<string>;
  /** Make a new key active and archive the previous one. */
  rotate(): Promise<ActiveIssuerKey>;
}

/** Raw ES256 signer: signs the JWS signing input and returns the 64-byte `r || s` signature. */
export type RawEs256Signer = (signingInput: Uint8Array) => Promise<Uint8Array>;

/**
 * Helper for KMS/HSM adapters: builds the compact JWS around a raw signature.
 * Serialization only; the signature itself comes from the adapter's `sign`.
 */
export async function signCompactJws(
  header: { alg: 'ES256'; kid: string; typ: string },
  payload: JWTPayload,
  sign: RawEs256Signer
): Promise<string> {
  const enc = new TextEncoder();
  const signingInput =
    base64url.encode(enc.encode(JSON.stringify(header))) +
    '.' +
    base64url.encode(enc.encode(JSON.stringify(payload)));
  const signature = await sign(enc.encode(signingInput));
  if (signature.length !== 64) {
    throw new Error(`Key provider returned a ${signature.length}-byte signature; ES256 needs 64 bytes (r||s)`);
  }
  return `${signingInput}.${base64url.encode(signature)}`;
}

let current: IssuerKeyProvider | null = null;

/** Register an adapter (KMS/HSM, or a test double). */
export function setKeyProvider(provider: IssuerKeyProvider | null): void {
  current = provider;
}

export function getKeyProvider(): IssuerKeyProvider {
  if (current) return current;
  const name = process.env['KEY_PROVIDER'] ?? 'file';
  if (name !== 'file') {
    throw new Error(
      `Unknown KEY_PROVIDER "${name}". Only "file" is built in; register an adapter with setKeyProvider().`
    );
  }
  return fileKeyProvider;
}
