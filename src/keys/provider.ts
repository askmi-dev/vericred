/**
 * KeyProvider — abstraction over issuer key storage & signing.
 *
 * Two implementations are planned (issue #19):
 *  - FileKeyProvider: current behaviour; P-256 keypair in JSON files (dev/demo grade).
 *  - KmsKeyProvider:  private key material never leaves the KMS/HSM; signing
 *                     happens inside the KMS (production/high-assurance grade).
 *
 * Design notes:
 *  - The interface exposes sign(), not raw private key material, because KMS-held
 *    keys are non-extractable. Modules that need to sign MUST go through sign().
 *  - publicJwk() is always available: the DID document / JWKS need public keys.
 */
export interface KeyProvider {
  /** Unique, stable identifier of the active key (kid). */
  getKid(): Promise<string>;

  /** Public JWK of the active key (for DID document / JWKS publishing). */
  getPublicJwk(): Promise<import('jose').JWK>;

  /**
   * All public keys (active + archived history) for DID document generation.
   * Archived keys stay published for verification until credentials expire.
   */
  listPublicKeys(): Promise<Array<{ publicKey: import('jose').JWK; kid: string }>>;

  /**
   * Sign a payload with the active key (ES256) and return a compact JWS.
   * For file-backed keys this is a local jose operation; for KMS-backed keys
   * the KMS performs the signature and private material never enters memory.
   */
  sign(payload: string): Promise<string>;

  /**
   * Rotate to a fresh keypair. Archives the current key (verification-only)
   * and makes the new key active. Returns the new kid.
   */
  rotate(): Promise<string>;

  /** Human-readable provider name for logs / admin UI. */
  readonly name: string;
}

export type KeyProviderType = 'file' | 'kms';
