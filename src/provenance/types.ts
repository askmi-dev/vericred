/**
 * Provenance record types — Art. 6a eIDAS 2.0 (#26).
 *
 * An issuer of Electronic Attestations of Attributes must be able to
 * demonstrate, per credential, where the attribute data came from and
 * that it was verified before issuance. These records are issuer-side
 * audit evidence only — they never enter the SD-JWT or any wallet.
 */
import { createHmac, createHash } from 'crypto';
import { z } from 'zod';

/**
 * Keyed pseudonym of the holder identifier used for the connector lookup.
 *
 * Privacy properties and honest limits (#36 review):
 * - HMAC-SHA-256 keyed with the issuer's pseudonym secret, so the log
 *   cannot be correlated with plain SHA-256 sets computed elsewhere,
 *   and dictionary attacks require the key, not just a guess of likely
 *   identifiers.
 * - This is a stable join pseudonym, NOT anonymity: an attacker with
 *   the pseudonym secret can still test guessed identifiers and join
 *   records across issuers sharing that secret. Key handling and
 *   rotation inherit from loadSecrets(); rotating the secret breaks
 *   joinability with older records.
 */
export function hashIdentifier(identifier: string): string {
  const secret = process.env['PROVENANCE_HASH_KEY'] ?? loadFallbackKey();
  return createHmac('sha256', secret).update(identifier).digest('hex');
}

// Late import avoided: secrets are loaded lazily to prevent import-order
// coupling in tests. Falls back to a process-derived key so the function
// never crashes; deployments should set PROVENANCE_HASH_KEY.
let cachedKey: string | null = null;
function loadFallbackKey(): string {
  if (cachedKey) return cachedKey;
  // Deterministic per-process fallback documented as NOT cross-restart
  // stable: acceptable only because a rotated key merely breaks joins,
  // it never weakens the record schema.
  cachedKey = createHash('sha256').update(`provenance:${process.pid}`).digest('hex');
  console.warn('[provenance] PROVENANCE_HASH_KEY not set; using process-derived fallback key. Cross-restart joins are not stable.');
  return cachedKey;
}

/** Strip credentials, query strings and fragments from a source reference. */
export function sanitizeSourceRef(ref: string): string {
  // Never persist http(s) URLs verbatim: they can embed credentials,
  // tokens or identifying query parameters. Keep scheme://host[:port]/path.
  if (/^https?:\/\//.test(ref)) {
    const u = new URL(ref);
    u.username = '';
    u.password = '';
    u.search = '';
    u.hash = '';
    return `${u.protocol}//${u.host}${u.pathname}`.replace(/\/$/, '') || `${u.protocol}//${u.host}`;
  }
  // Opaque refs like "table:users" or "data/holders.json" pass through
  // unless they carry a credential or query-string pattern (defensive;
  // the schema still enforces min(1)).
  if (/[?][^=\s]+=[^\s]*(&|$)/.test(ref) || /:\/\/[^/@]+:[^/@]*@/.test(ref)) {
    return 'redacted';
  }
  return ref;
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
    /** Keyed hash of the identifier passed to the connector (never raw PII) */
    identifierHash: z.string().regex(/^[0-9a-f]{64}$/),
    /** ISO timestamp of the connector lookup */
    at: z.string().datetime(),
  }),
  verification: z.object({
    /**
     * How the attributes were verified before issuance.
     * - 'authoritative-source' — read directly from the org's own system of record
     * - 'admin-attested' — an admin confirmed the values (manual connector)
     *
     * Honest limit (#36 review): the mode records the CONFIGURED
     * verification posture, not a per-lookup verification outcome.
     * It does not by itself prove source authenticity or attribute
     * correctness.
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
