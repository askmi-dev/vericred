/**
 * Provenance record types — Art. 6a eIDAS 2.0 (#26).
 *
 * An issuer of Electronic Attestations of Attributes must be able to
 * demonstrate, per credential, where the attribute data came from and
 * that it was verified before issuance. These records are issuer-side
 * audit evidence only — they never enter the SD-JWT or any wallet.
 */
import { createHash } from 'crypto';
import { z } from 'zod';

/**
 * SHA-256 hex of the holder identifier used for the connector lookup.
 * Never the raw identifier — the provenance log must not become a PII
 * store (mirrors the PII-masking-by-default posture of the admin APIs).
 */
export function hashIdentifier(identifier: string): string {
  return createHash('sha256').update(identifier).digest('hex');
}

export const provenanceRecordSchema = z.object({
  /** Unique id of this audit record (uuid) */
  provenanceId: z.string().uuid(),
  /** Joins to the SD-JWT `jti` (urn:uuid:...) of the issued credential */
  credentialId: z.string().startsWith('urn:uuid:'),
  /** Credential configuration id (template name), e.g. EmployeeCredential */
  credentialType: z.string().min(1),
  source: z.object({
    /** Connector type: json | postgres | mysql | rest | csv | manual */
    connectorType: z.enum(['json', 'postgres', 'mysql', 'rest', 'csv', 'manual']),
    /** Opaque description of the source, e.g. "table:users" or a file path */
    sourceRef: z.string().min(1),
  }),
  lookup: z.object({
    /** SHA-256 hex of the identifier passed to the connector (never raw PII) */
    identifierHash: z.string().regex(/^[0-9a-f]{64}$/),
    /** ISO timestamp of the connector lookup */
    at: z.string().datetime(),
  }),
  verification: z.object({
    /**
     * How the attributes were verified before issuance.
     * - 'authoritative-source' — read directly from the org's own system of record
     * - 'admin-attested' — an admin confirmed the values (manual connector)
     */
    mode: z.enum(['authoritative-source', 'admin-attested']),
  }),
  consentGate: z.object({
    /** Whether the holder consent flow reviewed and approved these claims */
    used: z.boolean(),
    /** Whether the signed claims are the consented snapshot (never recomputed) */
    claimsSnapshot: z.boolean(),
  }),
  /** ISO timestamp of credential issuance */
  issuedAt: z.string().datetime(),
  /** Issuer DID (did:web) that signed the credential */
  issuerDid: z.string().min(1),
});

export type ProvenanceRecord = z.infer<typeof provenanceRecordSchema>;
