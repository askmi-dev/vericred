/**
 * OID4VCI Holder Proof Verification
 *
 * Verifies a proof-of-possession JWT per OpenID for VCI spec.
 *
 * Expected holder proof JWT:
 *   Header: { "typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": { ...holder_public_jwk } }
 *   Payload: { "iss": "<holder_did>", "aud": "<issuer_url>", "iat": <unix_ts>, "nonce": "<c_nonce>" }
 *
 * Verification steps:
 *   1. Header typ === "openid4vci-proof+jwt"
 *   2. Header contains a jwk (holder public key — no DID resolution needed)
 *   3. JWT signature is valid against the header JWK
 *   4. aud matches the issuer URL
 *   5. iat is fresh (max MAX_PROOF_AGE_SECONDS old)
 *   6. nonce matches the c_nonce issued with the access token
 *   7. JWK thumbprint is computed (RFC 7638) → used as pairwise pseudonym input
 */

import { jwtVerify, importJWK, calculateJwkThumbprint } from 'jose';
import type { JWK } from 'jose';

const MAX_PROOF_AGE_SECONDS = 300; // 5 minutes

export interface HolderProofResult {
  /** RFC 7638 JWK thumbprint — used as input to pairwise pseudonym */
  holderThumbprint: string;
  /** Holder public JWK — stored in cnf.jkt of the issued credential */
  jwk: JWK;
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
): Promise<HolderProofResult> {
  // 1. Decode header without verification
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
      `Proof JWT typ must be "openid4vci-proof+jwt", got "${header['typ']}"`,
    );
  }

  // 3. Extract holder JWK from header
  const jwk = header['jwk'] as JWK | undefined;
  if (!jwk || typeof jwk !== 'object') {
    throw new ProofVerificationError('invalid_proof', 'Proof JWT header must include holder public key as "jwk"');
  }

  const alg = (header['alg'] as string | undefined) ?? 'ES256';

  // 4. Import key and verify signature + audience
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(jwk, alg);
    const result = await jwtVerify(proofJwt, key, {
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
  if (ageSeconds > MAX_PROOF_AGE_SECONDS) {
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

  return { holderThumbprint, jwk };
}
