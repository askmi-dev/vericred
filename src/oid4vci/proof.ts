/**
 * Verify an ES256 holder proof, audience, freshness and one-use issuer nonce binding.
 * Custom mode uses an embedded public JWK. EUDI requires kid=0 plus an authenticated
 * key attestation, configured provider/assurance trust and a valid signed storage status.
 * The caller consumes the nonce atomically after this verification succeeds.
 */

import { validateKeyAttestation } from '../wallet/attestation.js';
import { jwtVerify, importJWK, calculateJwkThumbprint } from 'jose';
import type { JWK } from 'jose';

const MAX_PROOF_AGE_SECONDS = 300; // 5 minutes

export interface HolderProofResult {
  /** RFC 7638 JWK thumbprint — used as input to pairwise pseudonym */
  holderThumbprint: string;
  /** Holder public JWK — stored in cnf.jwk of the issued credential */
  jwk: JWK;
  keyStorageExpiresAt?: number;
}

export class ProofVerificationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ProofVerificationError';
  }
}

export async function verifyHolderProofJwt(
  proofJwt: string,
  expectedAudience: string,
  expectedNonce: string,
  attestedCredentialLifetimeSeconds?: number,
): Promise<HolderProofResult> {
  // 1. Decode header without verification
  if (typeof proofJwt !== 'string' || proofJwt.length > 128 * 1024) throw new ProofVerificationError('invalid_proof', 'Invalid proof size');
  const parts = proofJwt.split('.');
  if (parts.length !== 3) {
    throw new ProofVerificationError('invalid_proof', 'Proof JWT must have three parts');
  }

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf-8')) as Record<string, unknown>;
  } catch {
    throw new ProofVerificationError('invalid_proof', 'Proof JWT header is not valid JSON');
  }

  // 2. Check typ
  if (header['typ'] !== 'openid4vci-proof+jwt') {
    throw new ProofVerificationError(
      'invalid_proof',
      'Proof JWT has an unsupported type',
    );
  }

  let attestation: Awaited<ReturnType<typeof validateKeyAttestation>> | undefined;
  let jwk: JWK | undefined;
  if (attestedCredentialLifetimeSeconds !== undefined) {
    // The pinned ETSI profile signs with attested_keys[0], selected by the literal kid "0".
    if (header.alg !== 'ES256' || header.kid !== '0' || typeof header.key_attestation !== 'string' ||
        header.jwk !== undefined || header.x5c !== undefined || header.jku !== undefined || header.x5u !== undefined) {
      throw new ProofVerificationError('invalid_proof', 'A key-attested ES256 proof with kid 0 is required');
    }
    try {
      attestation = await validateKeyAttestation(header.key_attestation, expectedNonce, attestedCredentialLifetimeSeconds);
      jwk = attestation.jwk;
    } catch { throw new ProofVerificationError('invalid_proof', 'Wallet key attestation could not be validated'); }
  } else {
    if (header.key_attestation !== undefined || header.kid !== undefined || header.x5c !== undefined || header.jku !== undefined || header.x5u !== undefined) {
      throw new ProofVerificationError('invalid_proof', 'Attested or certificate-selected proofs are not supported by this adapter');
    }
    jwk = header.jwk as JWK | undefined;
  }
  if (!jwk || typeof jwk !== 'object') throw new ProofVerificationError('invalid_proof', 'Proof JWT header must include holder public key as "jwk"');

  if (header.alg !== 'ES256' || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d) {
    throw new ProofVerificationError('invalid_proof', 'A public P-256 key and ES256 are required');
  }
  const alg = (header['alg'] as string | undefined) ?? 'ES256';

  // 4. Import key and verify signature + audience
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(jwk, alg);
    const result = await jwtVerify(proofJwt, key, {
      algorithms: ['ES256'],
      audience: expectedAudience,
      clockTolerance: 30,
    });
    payload = result.payload as Record<string, unknown>;
  } catch (e) {
    throw new ProofVerificationError(
      'invalid_proof_jwt',
      'Proof JWT verification failed: ' + (e as Error).message,
    );
  }

  // 5. Check iat freshness
  const iat = payload['iat'] as number | undefined;
  if (!iat || typeof iat !== 'number') {
    throw new ProofVerificationError('invalid_proof', 'Proof JWT missing iat');
  }
  const ageSeconds = Math.floor(Date.now() / 1000) - iat;
  if (ageSeconds < -30 || ageSeconds > MAX_PROOF_AGE_SECONDS) {
    throw new ProofVerificationError(
      'invalid_proof',
      `Proof JWT is too old (${ageSeconds}s > ${MAX_PROOF_AGE_SECONDS}s)`,
    );
  }

  // 6. Check nonce
  const nonce = payload['nonce'] as string | undefined;
  if (!nonce) {
    throw new ProofVerificationError('invalid_proof', 'Proof JWT missing nonce');
  }
  if (nonce !== expectedNonce) {
    throw new ProofVerificationError('invalid_nonce', 'Proof JWT nonce does not match c_nonce');
  }

  if (attestation) {
    try { await attestation.verifyStatus(); }
    catch { throw new ProofVerificationError('invalid_proof', 'Wallet key attestation status could not be validated'); }
  }

  // 7. Compute JWK thumbprint (RFC 7638)
  let holderThumbprint: string;
  try {
    holderThumbprint = await calculateJwkThumbprint(jwk, 'sha256');
  } catch (e) {
    throw new ProofVerificationError(
      'invalid_proof',
      'Cannot compute JWK thumbprint: ' + (e as Error).message,
    );
  }

  return { holderThumbprint, jwk, ...(attestation ? { keyStorageExpiresAt: attestation.storageExpiresAt } : {}) };
}
