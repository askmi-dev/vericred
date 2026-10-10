/**
 * KmsKeyProvider — interface + reference stub for hardware/managed KMS signing.
 *
 * STATUS: NOT IMPLEMENTED (fail-closed). This exists to fix the interface and
 * to make the audit story explicit: software keys for dev, hardware-backed for
 * production. Any attempt to instantiate it fails closed.
 *
 * Planned adapters (see issue #19): AWS KMS (ECC_P256 via Sign/Verify),
 * PKCS#11 HSM, Azure Key Vault. The adapter must ensure:
 *  - private key material never enters process memory (non-extractable keys)
 *  - sign() maps to the KMS sign operation (ES256 / ECDSA_P256_SHA256)
 *  - rotate() creates a new KMS key and re-publishes JWKS / did:web document
 */
import type { KeyProvider } from './provider.js';

export class KmsKeyProvider implements KeyProvider {
  readonly name = 'kms';

  constructor(_config: unknown) {
    // Fail closed: no KMS backend is wired up yet.
    throw new Error(
      '[keys] KMS provider is not implemented yet. Configure keys.provider: "file" or implement the adapter (issue #19).'
    );
  }

  async getKid(): Promise<string> {
    throw new Error('[keys] KMS provider not implemented.');
  }
  async getPublicJwk(): Promise<import('jose').JWK> {
    throw new Error('[keys] KMS provider not implemented.');
  }
  async listPublicKeys(): Promise<Array<{ publicKey: import('jose').JWK; kid: string }>> {
    throw new Error('[keys] KMS provider not implemented.');
  }
  async sign(_payload: string): Promise<string> {
    throw new Error('[keys] KMS provider not implemented.');
  }
  async rotate(): Promise<string> {
    throw new Error('[keys] KMS provider not implemented.');
  }
}
