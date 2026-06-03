import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { SignJWT } from 'jose';
import { createHmac, randomUUID } from 'crypto';
import { getIssuerKeyPair } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';
import { lookupAccessToken, rotateNonce } from './token.js';
import { assignStatusIndex } from '../revocation/statuslist.js';
import { getTemplate } from '../credentials/registry.js';
import { buildSdJwtPayload, combineSdJwt } from '../sdjwt/disclosures.js';
import { verifyHolderProofJwt, ProofVerificationError } from './proof.js';

// Register all built-in templates
import '../credentials/templates/age.js';
import '../credentials/templates/employee.js';
import '../credentials/templates/membership.js';

function pairwisePseudonym(secret: string, thumbprint: string, issuer: string, type: string): string {
  return 'did:askmi:pairwise:' + createHmac('sha256', secret)
    .update(thumbprint + '|' + issuer + '|' + type)
    .digest('base64url');
}

export function createCredentialRouter(pseudonymSecret: string): Router {
  const router = createRouter();

  router.post('/credentials', async (req, res) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) { res.status(401).json({ error: 'unauthorized' }); return; }

    const rawToken = auth.slice(7);
    const tokenEntry = lookupAccessToken(rawToken);
    if (!tokenEntry) { res.status(401).json({ error: 'invalid_token' }); return; }

    const { holderData, cNonce, cNonceExpiresAt } = tokenEntry;
    const config = loadConfig();
    const { privateKey, kid } = await getIssuerKeyPair();

    // ── Holder Proof-of-Possession ──────────────────────────────────────────
    const body = req.body as Record<string, unknown>;
    const proof = body['proof'] as Record<string, string> | undefined;
    const isDemoMode = process.env['DEMO_MODE'] === 'true';

    let holderThumbprint: string;
    let holderJwk: Record<string, unknown> | undefined;

    if (proof?.['proof_type'] === 'jwt' && proof['jwt']) {
      // Verify c_nonce has not expired
      if (Date.now() > cNonceExpiresAt) {
        res.status(400).json({ error: 'use_dpop_nonce', c_nonce: cNonce, c_nonce_expires_in: 0 });
        return;
      }

      try {
        const result = await verifyHolderProofJwt(proof['jwt'], config.issuer.url, cNonce);
        holderThumbprint = result.holderThumbprint;
        holderJwk = result.jwk as unknown as Record<string, unknown>;
      } catch (e) {
        const code = e instanceof ProofVerificationError ? e.code : 'invalid_proof';
        console.warn('[issuer] Holder proof rejected:', (e as Error).message);
        res.status(400).json({ error: code, error_description: (e as Error).message });
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
        error_description: 'A proof-of-possession JWT is required. Set DEMO_MODE=true to disable for testing.',
        c_nonce: cNonce,
        c_nonce_expires_in: Math.max(0, Math.floor((cNonceExpiresAt - Date.now()) / 1000)),
      });
      return;
    }

    // ── Template resolution ─────────────────────────────────────────────────
    let template;
    try {
      template = getTemplate(config.credential.type);
    } catch (e) {
      res.status(500).json({ error: 'unsupported_credential_type', detail: (e as Error).message });
      return;
    }

    const mappingErrors = template.validateMappings(config.fieldMappings);
    if (mappingErrors.length > 0) {
      res.status(500).json({ error: 'invalid_field_mappings', detail: mappingErrors });
      return;
    }

    const mappedData: Record<string, unknown> = {};
    for (const [templateField, sourceField] of Object.entries(config.fieldMappings)) {
      if (holderData[sourceField] !== undefined) {
        mappedData[templateField] = holderData[sourceField];
      }
    }

    let claims: Record<string, unknown>;
    try {
      claims = template.buildClaims(mappedData, config.templateOptions);
    } catch (e) {
      console.error('[issuer] buildClaims error:', e);
      res.status(400).json({ error: 'claim_build_failed', detail: (e as Error).message });
      return;
    }

    // ── SD-JWT selective disclosure ─────────────────────────────────────────
    const { sdHashes, disclosures } = buildSdJwtPayload(claims);

    // ── Revocation ──────────────────────────────────────────────────────────
    const credentialId = 'urn:uuid:' + randomUUID();
    const holderEmail = String(holderData['email'] ?? holderData['id'] ?? 'unknown');
    const { listId, statusIndex } = assignStatusIndex(credentialId, holderEmail);

    // ── Pairwise pseudonym — uses verified thumbprint ───────────────────────
    const pseudonym = pairwisePseudonym(pseudonymSecret, holderThumbprint, config.issuer.did, config.credential.type);

    const now = Math.floor(Date.now() / 1000);
    const exp = now + config.credential.expiresInDays * 86400;

    /**
     * SD-JWT-VC JWT payload (draft-ietf-oauth-sd-jwt-vc):
     * - cnf.jkt: JWK thumbprint — binds credential to holder key
     * - _sd_alg, _sd: selective disclosure per IETF SD-JWT spec
     * - No raw claim values in payload
     */
    const cnfClaim = holderJwk
      ? { cnf: { jkt: holderThumbprint } }
      : {};

    const jwt = await new SignJWT({
      vct: config.credential.type,
      jti: credentialId,
      iss: config.issuer.did,
      sub: pseudonym,
      iat: now,
      exp,
      ...cnfClaim,
      _sd_alg: 'sha-256',
      _sd: sdHashes,
      credentialStatus: {
        id: config.issuer.url + '/status/' + listId + '#' + statusIndex,
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListIndex: String(statusIndex),
        statusListCredential: config.issuer.url + '/status/' + listId,
      },
    })
      .setProtectedHeader({ alg: 'ES256', kid, typ: 'vc+sd-jwt' })
      .sign(privateKey);

    const credential = combineSdJwt(jwt, disclosures);

    // Rotate c_nonce after issuance (single-use; wallet can request more credentials with new nonce)
    const newNonce = rotateNonce(rawToken);

    console.log('[issuer] Issued ' + config.credential.type + ' ' + credentialId
      + ' bound=' + (holderJwk ? holderThumbprint.slice(0, 12) + '...' : 'none')
      + ' status=' + statusIndex);

    const response: Record<string, unknown> = { credential, format: 'dc+sd-jwt' };
    if (newNonce) {
      response['c_nonce'] = newNonce;
      response['c_nonce_expires_in'] = 300;
    }
    res.json(response);
  });

  return router;
}
