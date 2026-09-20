import { Router as createRouter, text } from 'express';
import { certificateSigner, getWalletProfile } from '../wallet/profile.js';
import { decryptMessage, issuerEncryptionKey, responseEncryption } from '../wallet/encryption.js';
import type { Router } from 'express';
import { audit } from '../storage/audit.js';
import { asyncHandler } from '../middleware/errors.js';
import { SignJWT, decodeJwt } from 'jose';
import { createHmac, randomUUID } from 'crypto';
import { getIssuerKeyPair } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';
import { lookupAccessToken, rotateNonce, lockIssuance, unlockIssuance, hasCredentialNonce, consumeCredentialNonce } from './token.js';
import { assignStatusIndex } from '../revocation/statuslist.js';
import { getTemplate, credentialVct, CredentialTemplate } from '../credentials/registry.js';
import { buildSdJwtPayload, combineSdJwt } from '../sdjwt/disclosures.js';
import { verifyHolderProofJwt, ProofVerificationError } from './proof.js';
import { logInterop } from './interop-logger.js';

// Register all built-in templates
import '../credentials/templates/age.js';
import '../credentials/templates/employee.js';
import '../credentials/templates/membership.js';

function pairwisePseudonym(secret: string, thumbprint: string, issuer: string, type: string): string {
  return 'did:askmi:pairwise:' + createHmac('sha256', secret)
    .update(thumbprint + '|' + issuer + '|' + type)
    .digest('base64url');
}

export function resolveMappedData(
  template: CredentialTemplate,
  fieldMappings: Record<string, string>,
  holderData: Record<string, unknown>
): { mappedData: Record<string, unknown>; errors: string[] } {
  const mappedData: Record<string, unknown> = {};
  const errors: string[] = [];

  for (const field of [...template.requiredFields, ...template.optionalFields]) {
    const source = Object.hasOwn(fieldMappings, field) ? fieldMappings[field] : undefined;
    if (source && Object.hasOwn(holderData, source) && holderData[source] !== undefined) {
      mappedData[field] = holderData[source];
    } else if (template.requiredFields.includes(field)) {
      errors.push('Required field "' + field + '" must be explicitly mapped to an available source field');
    }
  }

  return { mappedData, errors };
}

export function createCredentialRouter(pseudonymSecret: string): Router {
  const router = createRouter();
  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

  router.post('/credentials', text({ type: 'application/jwt', limit: '128kb' }), asyncHandler(async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) { res.status(401).json({ error: 'unauthorized' }); return; }

    const rawToken = auth.slice(7);
    const tokenEntry = lookupAccessToken(rawToken);
    if (!tokenEntry) { res.status(401).json({ error: 'invalid_token' }); return; }

    if (!lockIssuance(rawToken)) { res.status(409).json({ error: 'issuance_in_progress' }); return; }
    try {
    const { holderData, cNonce, cNonceExpiresAt } = tokenEntry;
    const config = { ...loadConfig(), issuer: tokenEntry.issuer, credential: tokenEntry.credential };
    const eudi = getWalletProfile() === 'eudi-android';
    const pair = await getIssuerKeyPair();
    const signer = eudi ? await certificateSigner('issuer') : null;
    const privateKey = signer?.privateKey ?? pair.privateKey;
    const kid = pair.kid;

    // ── Holder Proof-of-Possession ──────────────────────────────────────────
    let body: Record<string, unknown>;
    let encryptResponse: Awaited<ReturnType<typeof responseEncryption>> | undefined;
    try {
      if (eudi) {
        if (!req.is('application/jwt')) throw new Error('Encrypted credential request required');
        body = await decryptMessage(req.body, (await issuerEncryptionKey()).privateKey);
        encryptResponse = await responseEncryption(body.credential_response_encryption);
      } else {
        if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) throw new Error('Invalid request');
        body = req.body;
        if (body.credential_response_encryption !== undefined) throw new Error('Encryption not configured');
      }
    } catch { res.status(400).json({ error: 'invalid_encryption_parameters' }); return; }
    const finalProfile = body.proofs !== undefined || body.credential_configuration_id !== undefined;
    const authorizedType = tokenEntry.credentialType;
    if (eudi && !finalProfile) { res.status(400).json({ error: 'invalid_credential_request' }); return; }
    if (body.credential_identifier !== undefined ||
        (body.credential_configuration_id !== undefined && body.credential_configuration_id !== authorizedType) ||
        (body.format !== undefined && body.format !== (config.credential.format ?? 'dc+sd-jwt'))) {
      res.status(400).json({ error: 'invalid_credential_request' }); return;
    }
    let proof = body.proof as Record<string, string> | undefined;
    if (finalProfile) {
      const proofs = body.proofs as { jwt?: unknown[] } | undefined;
      if (body.proof !== undefined || body.credential_configuration_id !== authorizedType ||
          !proofs || Object.keys(proofs).length !== 1 || !Array.isArray(proofs.jwt) ||
          proofs.jwt.length !== 1 || typeof proofs.jwt[0] !== 'string') {
        res.status(400).json({ error: 'invalid_credential_request' }); return;
      }
      proof = { proof_type: 'jwt', jwt: proofs.jwt[0] };
    }
    const isDemoMode = process.env['DEMO_MODE'] === 'true' && process.env.NODE_ENV === 'development';

    let holderThumbprint: string;
    let keyStorageExpiresAt: number | undefined;
    let holderJwk: Record<string, unknown> | undefined;

    if (proof?.['proof_type'] === 'jwt' && proof['jwt']) {
      // Verify c_nonce has not expired
      if (!finalProfile && Date.now() >= cNonceExpiresAt) {
        res.status(400).json({ error: 'invalid_nonce', c_nonce: cNonce, c_nonce_expires_in: 0 });
        return;
      }

      try {
        const expectedNonce = finalProfile ? decodeJwt(proof.jwt).nonce : cNonce;
        if (typeof expectedNonce !== 'string' || (finalProfile && !hasCredentialNonce(expectedNonce))) {
          res.status(400).json({ error: 'invalid_nonce' }); return;
        }
        const result = await verifyHolderProofJwt(proof.jwt, config.issuer.url, expectedNonce, eudi ? config.credential.expiresInDays * 86400 : undefined);
        // Synchronous consumption after signature validation serializes races across access tokens.
        if (finalProfile && !consumeCredentialNonce(expectedNonce)) {
          res.status(400).json({ error: 'invalid_nonce' }); return;
        }
        keyStorageExpiresAt = result.keyStorageExpiresAt;
        holderThumbprint = result.holderThumbprint;
        holderJwk = result.jwk as unknown as Record<string, unknown>;
      } catch (e) {
        const code = e instanceof ProofVerificationError ? e.code : 'invalid_proof';
        const msg = (e as Error).message;
        console.warn('[issuer] Holder proof rejected:', msg);
        logInterop({ type: 'error', category: 'proof', message: msg, details: { code } });
        res.status(400).json({ error: code, error_description: msg });
        return;
      }
    } else if (isDemoMode) {
      // DEMO_MODE only: anonymous fallback — no holder binding
      console.warn('[issuer] DEMO_MODE: issuing credential without holder proof (no binding)');
      holderThumbprint = 'anonymous';
      holderJwk = undefined;
    } else {
      // Production: holder proof is required — fail closed
      res.status(400).json({
        error: 'holder_binding_required',
        error_description: 'A proof-of-possession JWT is required.',
        c_nonce: cNonce,
        c_nonce_expires_in: Math.max(0, Math.floor((cNonceExpiresAt - Date.now()) / 1000)),
      });
      return;
    }

    // ── Template resolution ─────────────────────────────────────────────────
    let template;
    const credentialType = tokenEntry.credentialType;
    try {
      template = getTemplate(credentialType);
    } catch (e) {
      res.status(500).json({ error: 'unsupported_credential_type', detail: (e as Error).message });
      return;
    }

    const { mappedData, errors: mappingErrors } = resolveMappedData(template, tokenEntry.fieldMappings, holderData);
    if (mappingErrors.length > 0) {
      logInterop({ type: 'warning', category: 'issuance', message: 'Field mapping failed', details: { errors: mappingErrors } });
      res.status(400).json({ error: 'invalid_field_mappings', detail: mappingErrors });
      return;
    }

    let claims: Record<string, unknown>;
    try {
      claims = template.buildClaims(mappedData, tokenEntry.templateOptions);
    } catch (e) {
      console.error('[issuer] buildClaims error:', e);
      res.status(400).json({ error: 'claim_build_failed', detail: (e as Error).message });
      return;
    }

    // ── SD-JWT selective disclosure ─────────────────────────────────────────
    const { sdHashes, disclosures } = buildSdJwtPayload(claims);

    // Fail closed if authority changed while key/proof verification awaited I/O.
    const currentIssuer = loadConfig().issuer;
    if (currentIssuer.url !== config.issuer.url || currentIssuer.did !== config.issuer.did) {
      res.status(409).json({ error: 'issuer_changed' }); return;
    }
    // ── Revocation ──────────────────────────────────────────────────────────
    const now = Math.floor(Date.now() / 1000);
    const exp = Math.min(now + config.credential.expiresInDays * 86400, keyStorageExpiresAt ?? Number.MAX_SAFE_INTEGER);
    const credentialId = 'urn:uuid:' + randomUUID();
    const holderEmail = String(holderData['email'] ?? holderData['id'] ?? 'unknown');
    const { listId, statusIndex } = assignStatusIndex(credentialId, holderEmail, credentialType, new Date(exp * 1000).toISOString());

    // ── Pairwise pseudonym — uses verified thumbprint ───────────────────────
    const pseudonym = pairwisePseudonym(pseudonymSecret, holderThumbprint, config.issuer.did, credentialType);


    /**
     * SD-JWT-VC JWT payload (draft-ietf-oauth-sd-jwt-vc):
     * - cnf.jwk: verified public JWK — binds credential to holder key
     * - _sd_alg, _sd: selective disclosure per IETF SD-JWT spec
     * - No raw claim values in payload
     */
    const cnfClaim = holderJwk
      ? { cnf: { jwk: holderJwk } }
      : {};

    const jwt = await new SignJWT({
      vct: credentialVct(credentialType),
      jti: credentialId,
      iss: eudi ? config.issuer.url : config.issuer.did,
      sub: pseudonym,
      iat: now,
      exp,
      ...cnfClaim,
      _sd_alg: 'sha-256',
      _sd: sdHashes,
       ...(eudi ? { status: { status_list: { idx: statusIndex, uri: config.issuer.url + '/status/token/' + listId } } } : { credentialStatus: {
        id: config.issuer.url + '/status/' + listId + '#' + statusIndex,
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListIndex: String(statusIndex),
        statusListCredential: config.issuer.url + '/status/' + listId,
      } }),
    })
      .setProtectedHeader({ alg: 'ES256', ...(signer ? { x5c: signer.x5c } : { kid }), typ: config.credential.format ?? 'dc+sd-jwt' })
      .sign(privateKey);

    const credential = combineSdJwt(jwt, disclosures);
    audit('credential.issued', 'issuer', credentialId, { credentialType });

    // Rotate c_nonce after issuance (single-use; wallet can request more credentials with new nonce)
    const newNonce = rotateNonce(rawToken);

    console.log('[issuer] Issued ' + credentialType + ' ' + credentialId
      + ' bound=' + (holderJwk ? holderThumbprint.slice(0, 12) + '...' : 'none')
      + ' status=' + statusIndex);

    const response: Record<string, unknown> = finalProfile
      ? { credentials: [{ credential }] }
      : { credential, format: config.credential.format ?? 'dc+sd-jwt' };
    logInterop({ type: 'info', category: 'issuance', message: `Issued ${credentialType}`, details: { credentialId } });
    if (newNonce && !finalProfile) {
      response['c_nonce'] = newNonce;
      response['c_nonce_expires_in'] = 300;
    }
    if (encryptResponse) res.type('application/jwt').send(await encryptResponse(response));
    else res.json(response);
    } catch {
      res.status(500).json({ error: 'issuance_failed' });
    } finally { unlockIssuance(rawToken); }
  }));

  return router;
}
