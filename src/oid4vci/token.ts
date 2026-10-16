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

// #31: offers/tokens live behind the OfferStore interface — file-backed
// by default (restart-safe), in-memory only when explicitly selected.
import { createOfferStore } from './state-store.js';
const store = createOfferStore();

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
  return store.sweep(Date.now());
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
  store.putPreAuthCode(code, {
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
  const entry = store.getAccessToken(token);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) {
    // Evict on access too, not just on the periodic sweep.
    store.deleteAccessToken(token);
    return null;
  }
  return entry;
}

/** Rotate c_nonce after successful credential issuance (single-use nonce). */
export function rotateNonce(token: string): string | null {
  const entry = store.getAccessToken(token);
  if (!entry || entry.expiresAt < Date.now()) return null;
  entry.cNonce = randomBytes(16).toString('hex');
  entry.cNonceExpiresAt = Date.now() + C_NONCE_TTL_MS;
  store.putAccessToken(token, entry); // persist rotated nonce (#31)
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

    // takePreAuthCode is get+delete: pre-auth codes are single-use.
    const entry = store.takePreAuthCode(code);
    if (!entry || entry.expiresAt < Date.now()) {
      logInterop({ type: 'warning', category: 'token', message: 'Invalid or expired pre-authorized code' });
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }
    logInterop({ type: 'info', category: 'token', message: 'Token issued via Pre-Auth code', details: { type: entry.credentialType } });
    const accessToken = randomBytes(32).toString('hex');
    const cNonce = randomBytes(16).toString('hex');

    store.putAccessToken(accessToken, {
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
