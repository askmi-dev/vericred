/**
 * Pre-authorized code flow token endpoint.
 * Validates the pre-auth code and issues an access token with a c_nonce
 * for holder proof-of-possession binding.
 */
import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { EncryptedMap } from '../storage/encrypted-map.js';
import { assertConfigUnchanged, loadConfig } from '../config/loader.js';
import type { VeriCredConfig } from '../config/types.js';
import { resolveTemplateConfig } from '../config/template.js';
import { getWalletProfile, type WalletProfile } from '../wallet/profile.js';
import { randomBytes } from 'crypto';
import { logInterop } from './interop-logger.js';

export interface GrantSnapshot {
  holderData: Record<string, unknown>;
  credentialType: string;
  fieldMappings: Record<string, string>;
  templateOptions: Record<string, unknown>;
  issuer: VeriCredConfig['issuer'];
  credential: VeriCredConfig['credential'];
  configRevision: number;
  walletProfile: WalletProfile;
}
export interface AccessTokenEntry extends GrantSnapshot {
  expiresAt: number;
  cNonce: string;
  cNonceExpiresAt: number;
}

const C_NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// Encrypted, persistent pre-authorized grants.
const preAuthCodes = new EncryptedMap<GrantSnapshot & { expiresAt: number }>('preauth-codes');
const accessTokens = new EncryptedMap<AccessTokenEntry>('access-tokens');
const busy = new Set<string>();
const credentialNonces = new EncryptedMap<{ expiresAt: number }>('credential-nonces');
export function hasCredentialNonce(nonce: string): boolean {
  return (credentialNonces.get(nonce)?.expiresAt ?? 0) > Date.now();
}
export function consumeCredentialNonce(nonce: string): boolean {
  if (!hasCredentialNonce(nonce)) return false;
  credentialNonces.delete(nonce); return true;
}
function pruneExpired() {
  const now = Date.now();
  for (const [key, value] of credentialNonces) if (value.expiresAt <= now) credentialNonces.delete(key);
  for (const [key, value] of preAuthCodes) if (value.expiresAt <= now) preAuthCodes.delete(key);
  for (const [key, value] of accessTokens) if (value.expiresAt <= now) { accessTokens.delete(key); busy.delete(key); }
}
export function lockIssuance(token: string): boolean {
  pruneExpired();
  if (busy.has(token) || !accessTokens.has(token)) return false;
  busy.add(token); return true;
}
export function unlockIssuance(token: string) { busy.delete(token); }


export function issuePreAuthCode(holderData: Record<string, unknown>, credentialType?: string, snapshot = loadConfig()): string {
  assertConfigUnchanged(snapshot);
  pruneExpired();
  const code = randomBytes(16).toString('hex');
  const type = credentialType ?? snapshot.credential.type;
  preAuthCodes.set(code, {
    ...resolveTemplateConfig(snapshot, type),
    holderData: structuredClone(holderData),
    issuer: structuredClone(snapshot.issuer),
    credential: { ...snapshot.credential, type },
    configRevision: snapshot.revision ?? 0,
    walletProfile: getWalletProfile(),
    expiresAt: Date.now() + 10 * 60 * 1000,
    credentialType: type,
  });
  return code;
}
/** Old incomplete grants cannot safely recover policy from mutable live configuration. */
function validSnapshot(entry: Partial<GrantSnapshot>): entry is GrantSnapshot {
  const current = loadConfig();
  return typeof entry.credentialType === 'string' && !!entry.fieldMappings && !!entry.templateOptions &&
    !!entry.credential && entry.credential.type === entry.credentialType &&
    Number.isInteger(entry.configRevision) && entry.walletProfile === getWalletProfile() && !!entry.issuer &&
    entry.issuer.url === current.issuer.url && entry.issuer.did === current.issuer.did;
}

export function lookupAccessToken(token: string): AccessTokenEntry | null {
  const entry = accessTokens.get(token);
  if (!entry || entry.expiresAt <= Date.now() || !validSnapshot(entry)) return null;
  return entry;
}

/** Rotate c_nonce after successful credential issuance (single-use nonce). */
export function rotateNonce(token: string): string | null {
  const entry = accessTokens.get(token);
  if (!entry || entry.expiresAt <= Date.now() || !validSnapshot(entry)) return null;
  entry.cNonce = randomBytes(16).toString('hex');
  entry.cNonceExpiresAt = Date.now() + C_NONCE_TTL_MS;
  accessTokens.set(token, entry);
  return entry.cNonce;
}

export function createTokenRouter(): Router {
  const router = createRouter();
  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  router.post('/nonce', (_req, res) => {
    pruneExpired();
    const nonce = randomBytes(32).toString('base64url');
    credentialNonces.set(nonce, { expiresAt: Date.now() + C_NONCE_TTL_MS });
    res.json({ c_nonce: nonce });
  });

  router.post('/token', (req, res) => {
    const { grant_type, 'pre-authorized_code': code } = (req.body ?? {}) as Record<string, string>;

    if (grant_type !== 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
      logInterop({ type: 'error', category: 'token', message: 'Unsupported grant type', details: { grant_type } });
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }

    if (typeof code !== 'string') { res.status(400).json({ error: 'invalid_request' }); return; }
    const entry = preAuthCodes.get(code);
    if (!entry || entry.expiresAt <= Date.now() || !validSnapshot(entry)) {
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
      fieldMappings: entry.fieldMappings, templateOptions: entry.templateOptions,
      issuer: entry.issuer, credential: entry.credential, configRevision: entry.configRevision, walletProfile: entry.walletProfile,
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
