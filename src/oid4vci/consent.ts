/**
 * Pre-issuance consent gate.
 *
 * For templates with requiresConsent: true, POST /offer creates a
 * ConsentRecord instead of immediately issuing a pre-authorized code.
 * The holder reviews the claims that will be signed into their credential
 * and approves or declines via GET/POST /consent/:id/*. Only on approval
 * does issuePreAuthCode get called -- enforced by construction: this file
 * is the only caller of issuePreAuthCode on the consent-gated path.
 *
 * Fail-closed: unknown, expired, or already-decided consent ids always
 * reject (404/410). Nothing here ever defaults to allow.
 */
import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { randomBytes } from 'crypto';
import { z } from 'zod';
import { issuePreAuthCode, buildCredentialOffer } from './token.js';

export type ConsentVerdict = 'PENDING' | 'APPROVED' | 'DECLINED';

export interface ConsentClaim {
  key: string;
  label: string;
  value: unknown;
  required: boolean;
}

interface PendingConsentRecord {
  consentId: string;
  credentialType: string;
  holderData: Record<string, unknown>;
  claims: ConsentClaim[];
  verdict: 'PENDING';
  createdAt: number;
  expiresAt: number;
}

/**
 * What a decided record becomes, immediately -- not a full ConsentRecord
 * with a verdict field changed in place. holderData and claims (the only
 * PII/claim-value-bearing fields) are discarded the moment a decision is
 * made, not retained until the 24h TTL like everything else here. Keeps
 * only what GET/POST /consent/:id/* need to keep answering 410/404
 * correctly for the rest of the original window.
 */
interface DecidedConsentTombstone {
  consentId: string;
  verdict: 'APPROVED' | 'DECLINED';
  decidedAt: number;
  expiresAt: number;
}

type ConsentRecord = PendingConsentRecord | DecidedConsentTombstone;

const CONSENT_TTL_MS = 24 * 60 * 60 * 1000; // 24h -- a human reading a page
// needs longer than a wallet's programmatic pre-auth-code redemption (10 min).

// Hard ceiling on concurrently PENDING records (the only variant carrying
// PII/claim values) -- bounds memory independent of the TTL sweep, e.g.
// against an admin-side burst or a sweep interval that hasn't run yet.
// Tombstones aren't counted: they carry no PII and are already minimal.
const MAX_PENDING_RECORDS = 10_000;

const consentRecords = new Map<string, ConsentRecord>();

/**
 * Deletes every record past its expiresAt, regardless of verdict --
 * PENDING, DECLINED and APPROVED records all carry the same TTL set at
 * creation, so this bounds how long raw holderData and the claim
 * snapshot are retained to CONSENT_TTL_MS after creation, not forever.
 * Without this, a long-running issuer's consentRecords Map grows without
 * bound and keeps holder PII indefinitely even for offers long since
 * decided or expired. Exported so tests can trigger it deterministically
 * instead of waiting on the real interval.
 */
export function sweepExpiredConsentRecords(): number {
  let swept = 0;
  const now = Date.now();
  for (const [id, record] of consentRecords) {
    if (record.expiresAt < now) {
      consentRecords.delete(id);
      swept++;
    }
  }
  return swept;
}

const sweepTimer = setInterval(sweepExpiredConsentRecords, 15 * 60 * 1000);
sweepTimer.unref?.();

// Human-readable labels for known output claim keys. Falls back to the raw
// key for anything not listed here (new templates/claims still work, just
// less polished until a label is added).
const claimLabels: Record<string, string> = {
  age_over_18: 'That you are over 18',
  age_over_21: 'That you are over 21',
  age_attested_at: 'Date this credential was issued',
  jurisdiction: 'Your jurisdiction',
  given_name: 'Your first name',
  family_name: 'Your last name',
  organization: 'Your organization',
  role: 'Your role',
  department: 'Your department',
  // Keys below are the templates' actual *output* claim names (snake_case,
  // from buildClaims()'s return value) -- not their input/requiredFields
  // names (e.g. EmployeeCredential's input is `employeeId`, but its output
  // claim is `employee_id`). Using the wrong one here would only ever
  // silently fall back to the raw key, never error, so this is easy to
  // get wrong without a template actually exercised through the gate.
  employee_id: 'Your employee ID',
  valid_until: 'Valid until date',
  membership_type: 'Your membership type',
  member_id: 'Your member ID',
  member_since: 'Member since date',
  member_until: 'Member until date',
};

/**
 * Builds the claim list shown to the holder from the actual *output*
 * claims (template.buildClaims()'s return value) -- never from raw input
 * fields. E.g. AgeCredential's consent screen must show "age_over_18",
 * never the raw dateOfBirth it was derived from. Includes each claim's
 * actual value, not just its key/label, so approval is genuinely informed
 * -- a holder can't meaningfully approve "a role will be signed" without
 * seeing which role.
 *
 * v1 is binary accept/decline only (no per-claim decline yet), so every
 * claim is marked required: true here -- there's no partial-disclosure
 * path for this flag to drive yet. See docs/CONSENT_FLOW_PLAN.md's
 * deferred per-field granularity.
 */
export function buildClaimsList(claims: Record<string, unknown>): ConsentClaim[] {
  return Object.keys(claims).map((key) => ({
    key,
    label: claimLabels[key] ?? key,
    value: claims[key],
    required: true,
  }));
}

/**
 * Returns null when the pending-record cap is reached -- fails closed,
 * never evicts someone else's pending record to make room.
 *
 * holderData and claims are deep-cloned before storage via
 * structuredClone(): without this, the caller's own references (e.g.
 * offer.ts's `holderData`/`claims` locals) alias the stored record, so
 * any later in-place mutation of those locals -- today or in a future
 * change -- would silently corrupt what the holder already reviewed.
 * structuredClone() also rejects unsupported values (functions, etc.)
 * by throwing rather than silently dropping or stringifying them;
 * Express's default error handling turns that into a 500, which is the
 * right fail-closed behavior for a claim value a template should never
 * have produced in the first place.
 */
export function createConsentRecord(
  holderData: Record<string, unknown>,
  credentialType: string,
  claims: ConsentClaim[]
): string | null {
  let pendingCount = 0;
  for (const r of consentRecords.values()) {
    if (r.verdict === 'PENDING') pendingCount++;
  }
  if (pendingCount >= MAX_PENDING_RECORDS) return null;

  const consentId = randomBytes(16).toString('hex');
  consentRecords.set(consentId, {
    consentId,
    credentialType,
    holderData: structuredClone(holderData),
    claims: structuredClone(claims),
    verdict: 'PENDING',
    createdAt: Date.now(),
    expiresAt: Date.now() + CONSENT_TTL_MS,
  });
  return consentId;
}

/**
 * Returns null for unknown or expired records -- never resurrects one
 * past its TTL. Returns a deep clone, not the stored record itself, so
 * callers (including HTTP handlers building a JSON response) can never
 * mutate consentRecords' internal state through what they're handed.
 */
export function getConsentRecord(consentId: string): ConsentRecord | null {
  const record = consentRecords.get(consentId);
  if (!record) return null;
  if (record.expiresAt < Date.now()) {
    // Evict on access too, not just on the periodic sweep -- no reason to
    // keep holding a dead record's PII once something's already touched it.
    consentRecords.delete(consentId);
    return null;
  }
  return structuredClone(record);
}

export function decideConsent(
  consentId: string,
  approved: boolean
): { offer?: Record<string, unknown>; offer_uri?: string; declined?: true } | { error: string } {
  const record = getConsentRecord(consentId);
  if (!record) {
    return { error: 'invalid_or_expired' };
  }
  if (record.verdict !== 'PENDING') {
    return { error: 'already_decided' };
  }

  if (!approved) {
    // Replace the full record with a tombstone -- holderData and claims
    // are discarded now, not retained until expiresAt like a PENDING
    // record. The tombstone keeps only what's needed to keep answering
    // 410 for the rest of the original window.
    consentRecords.set(consentId, {
      consentId,
      verdict: 'DECLINED',
      decidedAt: Date.now(),
      expiresAt: record.expiresAt,
    });
    return { declined: true };
  }

  // Reissue exactly the claim values the holder reviewed and approved --
  // never recompute from live config/mappings, which could have changed
  // during the (up to 24h) consent window, or drift across a date
  // boundary for a date-dependent claim like age_over_18.
  const claimsSnapshot = Object.fromEntries(record.claims.map((c) => [c.key, c.value]));
  const code = issuePreAuthCode(record.holderData, record.credentialType, claimsSnapshot);
  const offer = buildCredentialOffer(code, record.credentialType);

  consentRecords.set(consentId, {
    consentId,
    verdict: 'APPROVED',
    decidedAt: Date.now(),
    expiresAt: record.expiresAt,
  });

  return offer;
}

const decideConsentSchema = z.object({ approved: z.boolean() });

export function createConsentRouter(): Router {
  const router = createRouter();

  router.get('/consent/:id([0-9a-f]{32})/claims', (req, res) => {
    const record = getConsentRecord(req.params.id);
    if (!record || record.verdict !== 'PENDING') {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    res.json({ credentialType: record.credentialType, claims: record.claims, expiresAt: record.expiresAt });
  });

  router.post('/consent/:id([0-9a-f]{32})/decide', (req, res) => {
    const parsed = decideConsentSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'invalid_request', details: parsed.error.flatten() });
      return;
    }

    const result = decideConsent(req.params.id, parsed.data.approved);
    if ('error' in result) {
      const status = result.error === 'already_decided' ? 410 : 404;
      res.status(status).json(result);
      return;
    }
    res.json(result);
  });

  return router;
}
