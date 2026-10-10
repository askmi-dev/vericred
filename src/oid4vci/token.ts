/**
 * Pre-authorized code flow token endpoint.
 * Validates the pre-auth code and issues an access token with a c_nonce
 * for holder proof-of-possession binding.
 */
import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { randomBytes } from 'crypto';
import { logInterop } from './interop-logger.js';
import { loadConfig } from '../config/loader.js';

export interface AccessTokenEntry {
  holderData: Record<string, unknown>;
  expiresAt: number;
  cNonce: string;
  cNonceExpiresAt: number;
  credentialType?: string;
  claims?: Record<string, unknown>;
}

const C_NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// In-memory: pre-auth code -> holder data
const preAuthCodes = new Map<string, {
  holderData: Record<string, unknown>;
  expiresAt: number;
  credentialType?: string;
  claims?: Record<string, unknown>;
}>();
const accessTokens = new Map<string, AccessTokenEntry>();

/**
 * Both maps carry holderData (and, for the consent-gate path, a claims
 * snapshot) -- the same PII-retention concern consent.ts's
 * sweepExpiredConsentRecords addresses, for the two stores downstream of
 * it. A pre-auth code that's never redeemed, or an access token past its
 * 5-minute window, otherwise sits here indefinitely: expiresAt is only
 * ever checked at lookup time, never swept proactively. Exported so
 * tests can trigger it deterministically instead of waiting on the real
 * interval.
 */
export function sweepExpiredTokens(): { preAuthCodes: number; accessTokens: number } {
  const now = Date.now();
  let sweptPreAuthCodes = 0;
  for (const [code, entry] of preAuthCodes) {
    if (entry.expiresAt < now) {
      preAuthCodes.delete(code);
      sweptPreAuthCodes++;
    }
  }
  let sweptAccessTokens = 0;
  for (const [token, entry] of accessTokens) {
    if (entry.expiresAt < now) {
      accessTokens.delete(token);
      sweptAccessTokens++;
    }
  }
  return { preAuthCodes: sweptPreAuthCodes, accessTokens: sweptAccessTokens };
}

const tokenSweepTimer = setInterval(sweepExpiredTokens, 15 * 60 * 1000);
tokenSweepTimer.unref?.();

/**
 * `claims`, when given, is a snapshot already computed and shown to the
 * holder (the consent-gate path) -- /credentials must issue exactly this,
 * never recompute live, or the signed credential could drift from what
 * was reviewed (a config change or a date boundary crossed during the
 * consent window). Omitted for the non-consent path, where /credentials
 * computes claims live as it always has.
 */
export function issuePreAuthCode(
  holderData: Record<string, unknown>,
  credentialType?: string,
  claims?: Record<string, unknown>
): string {
  const code = randomBytes(16).toString('hex');
  preAuthCodes.set(code, {
    holderData,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 min
    credentialType,
    claims,
  });
  return code;
}

/**
 * Build a standard OID4VCI credential-offer object + deep-link URI from a
 * pre-authorized code. Shared by POST /offer (issues immediately) and the
 * consent gate's decideConsent (issues only after holder approval) so the
 * offer shape is defined exactly once.
 */
export function buildCredentialOffer(code: string, credentialType: string): {
  offer: Record<string, unknown>;
  offer_uri: string;
} {
  const config = loadConfig();

  const offer = {
    credential_issuer: config.issuer.url,
    credential_configuration_ids: [credentialType],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': code,
        user_pin_required: false,
      },
    },
  };

  const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
  return { offer, offer_uri: offerUri };
}

export function lookupAccessToken(token: string): AccessTokenEntry | null {
  const entry = accessTokens.get(token);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    // Evict on access too, not just on the periodic sweep.
    accessTokens.delete(token);
    return null;
  }
  return entry;
}

/** Rotate c_nonce after successful credential issuance (single-use nonce). */
export function rotateNonce(token: string): string | null {
  const entry = accessTokens.get(token);
  if (!entry || entry.expiresAt < Date.now()) return null;
  entry.cNonce = randomBytes(16).toString('hex');
  entry.cNonceExpiresAt = Date.now() + C_NONCE_TTL_MS;
  return entry.cNonce;
}

export function createTokenRouter(): Router {
  const router = createRouter();

  router.post('/token', (req, res) => {
    const { grant_type, 'pre-authorized_code': code } = req.body as Record<string, string>;

    if (grant_type !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      logInterop({ type: 'error', category: 'token', message: 'Unsupported grant type', details: { grant_type } });
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }

    const entry = preAuthCodes.get(code);
    if (!entry || entry.expiresAt < Date.now()) {
      preAuthCodes.delete(code);
      logInterop({ type: 'warning', category: 'token', message: 'Invalid or expired pre-authorized code' });
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }

    preAuthCodes.delete(code);
    logInterop({ type: 'info', category: 'token', message: 'Token issued via Pre-Auth code', details: { type: entry.credentialType } });
    const accessToken = randomBytes(32).toString('hex');
    const cNonce = randomBytes(16).toString('hex');

    accessTokens.set(accessToken, {
      holderData: entry.holderData,
      expiresAt: Date.now() + 5 * 60 * 1000,
      cNonce,
      cNonceExpiresAt: Date.now() + C_NONCE_TTL_MS,
      credentialType: entry.credentialType,
      claims: entry.claims,
    });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 300,
      c_nonce: cNonce,
      c_nonce_expires_in: 300,
    });
  });

  return router;
}
