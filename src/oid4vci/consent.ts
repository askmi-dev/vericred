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

export type ConsentVerdict = 'PENDING' | 'APPROVED' | 'DECLINED' | 'EXPIRED';

export interface ConsentClaim {
  key: string;
  label: string;
  value: unknown;
  required: boolean;
}

interface ConsentRecord {
  consentId: string;
  credentialType: string;
  holderData: Record<string, unknown>;
  claims: ConsentClaim[];
  verdict: ConsentVerdict;
  createdAt: number;
  decidedAt?: number;
  expiresAt: number;
}

const CONSENT_TTL_MS = 24 * 60 * 60 * 1000; // 24h -- a human reading a page
// needs longer than a wallet's programmatic pre-auth-code redemption (10 min).

const consentRecords = new Map<string, ConsentRecord>();

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
  employeeId: 'Your employee ID',
  validUntil: 'Valid until date',
  membershipType: 'Your membership type',
  memberId: 'Your member ID',
  memberSince: 'Member since date',
  memberUntil: 'Member until date',
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

export function createConsentRecord(
  holderData: Record<string, unknown>,
  credentialType: string,
  claims: ConsentClaim[]
): string {
  const consentId = randomBytes(16).toString('hex');
  consentRecords.set(consentId, {
    consentId,
    credentialType,
    holderData,
    claims,
    verdict: 'PENDING',
    createdAt: Date.now(),
    expiresAt: Date.now() + CONSENT_TTL_MS,
  });
  return consentId;
}

/** Returns null for unknown or expired records -- never resurrects one past its TTL. */
export function getConsentRecord(consentId: string): ConsentRecord | null {
  const record = consentRecords.get(consentId);
  if (!record) return null;
  if (record.expiresAt < Date.now()) {
    if (record.verdict === 'PENDING') record.verdict = 'EXPIRED';
    return null;
  }
  return record;
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

  record.decidedAt = Date.now();

  if (!approved) {
    record.verdict = 'DECLINED';
    return { declined: true };
  }

  record.verdict = 'APPROVED';
  // Reissue exactly the claim values the holder reviewed and approved --
  // never recompute from live config/mappings, which could have changed
  // during the (up to 24h) consent window, or drift across a date
  // boundary for a date-dependent claim like age_over_18.
  const claimsSnapshot = Object.fromEntries(record.claims.map((c) => [c.key, c.value]));
  const code = issuePreAuthCode(record.holderData, record.credentialType, claimsSnapshot);
  return buildCredentialOffer(code, record.credentialType);
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
