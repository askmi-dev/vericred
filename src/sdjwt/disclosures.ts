/**
 * IETF SD-JWT Disclosure Serialization
 * draft-ietf-oauth-selective-disclosure-jwt
 *
 * Disclosure format:
 *   base64url(JSON.stringify([salt, claim_name, claim_value]))
 *
 * Hash in JWT _sd array:
 *   base64url(SHA-256(encoded_disclosure))
 *
 * Combined credential:
 *   <issuer-signed-jwt>~<disclosure1>~<disclosure2>~
 *
 * Policy: ALL template claims are selectively disclosable by default.
 * Raw claim values never appear in the JWT payload.
 * Structural claims (iss, iat, exp, vct, sub, jti, _sd_alg, credentialStatus) stay top-level.
 */

import { randomBytes, createHash } from 'crypto';

/**
 * Create a single SD-JWT disclosure for one claim.
 *
 * Returns:
 *   encoded  — the base64url-encoded disclosure (appended to JWT after ~)
 *   digest   — base64url(SHA-256(encoded)) — goes into _sd array in JWT payload
 */
export function createDisclosure(
  claimName: string,
  claimValue: unknown,
): { encoded: string; digest: string } {
  const salt = randomBytes(16).toString('base64url');
  const disclosure = JSON.stringify([salt, claimName, claimValue]);
  const encoded = Buffer.from(disclosure).toString('base64url');
  const digest = createHash('sha256').update(encoded).digest('base64url');
  return { encoded, digest };
}

/**
 * Build SD-JWT payload components from a claims map.
 *
 * All claims become selective disclosures (Option A: minimization by construction).
 * Returns:
 *   sdHashes    — array of digests for the _sd field in JWT payload
 *   disclosures — array of encoded disclosures to append after ~
 */
export function buildSdJwtPayload(claims: Record<string, unknown>): {
  sdHashes: string[];
  disclosures: string[];
} {
  const sdHashes: string[] = [];
  const disclosures: string[] = [];

  for (const [name, value] of Object.entries(claims)) {
    const { encoded, digest } = createDisclosure(name, value);
    sdHashes.push(digest);
    disclosures.push(encoded);
  }

  return { sdHashes, disclosures };
}

/**
 * Combine a signed JWT with its disclosures into the SD-JWT Combined Format.
 *
 * Format: <jwt>~<disclosure1>~<disclosure2>~
 * The trailing ~ is required by the spec even when all disclosures are included.
 */
export function combineSdJwt(jwt: string, disclosures: string[]): string {
  return jwt + '~' + disclosures.join('~') + '~';
}

/**
 * Decode a disclosure back to [salt, claimName, claimValue].
 * Used in tests and verification contexts.
 */
export function decodeDisclosure(encoded: string): [string, string, unknown] {
  const json = Buffer.from(encoded, 'base64url').toString('utf-8');
  const parsed = JSON.parse(json) as unknown[];
  if (!Array.isArray(parsed) || parsed.length !== 3) {
    throw new Error('Invalid disclosure: expected [salt, name, value] array');
  }
  return parsed as [string, string, unknown];
}

/**
 * Verify that a disclosure matches its digest.
 * Used in verifier-side logic.
 */
export function verifyDisclosureDigest(encoded: string, expectedDigest: string): boolean {
  const actual = createHash('sha256').update(encoded).digest('base64url');
  return actual === expectedDigest;
}
