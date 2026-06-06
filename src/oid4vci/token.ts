/**
 * Pre-authorized code flow token endpoint.
 * Validates the pre-auth code and issues an access token with a c_nonce
 * for holder proof-of-possession binding.
 */
import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { randomBytes } from 'crypto';
import { logInterop } from './interop-logger.js';

export interface AccessTokenEntry {
  holderData: Record<string, unknown>;
  expiresAt: number;
  cNonce: string;
  cNonceExpiresAt: number;
  credentialType?: string;
}

const C_NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// In-memory: pre-auth code -> holder data
const preAuthCodes = new Map<string, {
  holderData: Record<string, unknown>;
  expiresAt: number;
  credentialType?: string;
}>();
const accessTokens = new Map<string, AccessTokenEntry>();

export function issuePreAuthCode(holderData: Record<string, unknown>, credentialType?: string): string {
  const code = randomBytes(16).toString('hex');
  preAuthCodes.set(code, {
    holderData,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 min
    credentialType
  });
  return code;
}

export function lookupAccessToken(token: string): AccessTokenEntry | null {
  const entry = accessTokens.get(token);
  if (!entry || entry.expiresAt < Date.now()) return null;
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
