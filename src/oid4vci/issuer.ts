import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { SignJWT } from 'jose';
import { createHmac, randomUUID } from 'crypto';
import { getIssuerKeyPair } from '../keys/manager.js';
import { getIssuerSigningIdentity } from '../keys/x5c.js';
import { loadConfig } from '../config/loader.js';
import { lookupAccessToken, rotateNonce } from './token.js';
import { assignStatusIndex } from '../revocation/statuslist.js';
import { getTemplate, CredentialTemplate } from '../credentials/registry.js';
import { buildSdJwtPayload, combineSdJwt } from '../sdjwt/disclosures.js';
import { verifyHolderProofJwt, ProofVerificationError } from './proof.js';
import { logInterop } from './interop-logger.js';
import { DEFAULT_BATCH_SIZE } from './metadata.js';

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

  const normalize = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');

  const templateFields = [...template.requiredFields, ...template.optionalFields];

  for (const templateField of templateFields) {
    // 1. Try explicit mapping from config
    const explicitSourceField = fieldMappings[templateField];
    if (explicitSourceField && holderData[explicitSourceField] !== undefined) {
      mappedData[templateField] = holderData[explicitSourceField];
      continue;
    }

    // 2. Fallback: try direct match (no mapping required if key matches exactly)
    if (holderData[templateField] !== undefined) {
      mappedData[templateField] = holderData[templateField];
      continue;
    }

    // 3. Fallback: smart camelCase/snake_case/case-insensitive match
    const normTemplate = normalize(templateField);
    let matched = false;
    for (const k of Object.keys(holderData)) {
      if (normalize(k) === normTemplate) {
        mappedData[templateField] = holderData[k];
        matched = true;
        break;
      }
    }

    // 4. Validate if required field is still missing
    if (!matched && template.requiredFields.includes(templateField)) {
      errors.push(`Required field "${templateField}" could not be resolved from holder data`);
    }
  }

  return { mappedData, errors };
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
    // Two request shapes:
    //   proof:  { proof_type: 'jwt', jwt }  — single credential (pre-1.0 drafts)
    //   proofs: { jwt: [jwt, ...] }         — OID4VCI 1.0 batch: one copy per
    //                                         proof, each bound to its own key
    const body = req.body as Record<string, unknown>;
    const proof = body['proof'] as Record<string, string> | undefined;
    const isBatch = body['proofs'] !== undefined;
    const isDemoMode = process.env['DEMO_MODE'] === 'true';
    const batchSize = config.credential.batchSize ?? DEFAULT_BATCH_SIZE;

    let proofJwts: string[] = [];
    if (isBatch) {
      const jwts = (body['proofs'] as { jwt?: unknown } | null)?.jwt;
      if (proof || !Array.isArray(jwts) || jwts.length === 0 || !jwts.every(j => typeof j === 'string' && j)) {
        res.status(400).json({
          error: 'invalid_credential_request',
          error_description: 'proofs.jwt must be a non-empty array of proof JWTs, and cannot be combined with proof',
        });
        return;
      }
      if (jwts.length > batchSize) {
        res.status(400).json({
          error: 'invalid_credential_request',
          error_description: `At most ${batchSize} proofs per request (batch_credential_issuance.batch_size)`,
        });
        return;
      }
      proofJwts = jwts as string[];
    } else if (proof?.['proof_type'] === 'jwt' && proof['jwt']) {
      proofJwts = [proof['jwt']];
    }

    /** One entry per credential copy to issue. */
    const holders: Array<{ thumbprint: string; jwk?: Record<string, unknown> }> = [];

    if (proofJwts.length > 0) {
      // Verify c_nonce has not expired
      if (Date.now() > cNonceExpiresAt) {
        res.status(400).json({ error: 'use_dpop_nonce', c_nonce: cNonce, c_nonce_expires_in: 0 });
        return;
      }

      for (const proofJwt of proofJwts) {
        try {
          const result = await verifyHolderProofJwt(proofJwt, config.issuer.url, cNonce);
          holders.push({ thumbprint: result.holderThumbprint, jwk: result.jwk as unknown as Record<string, unknown> });
        } catch (e) {
          const code = e instanceof ProofVerificationError ? e.code : 'invalid_proof';
          const msg = (e as Error).message;
          console.warn('[issuer] Holder proof rejected:', msg);
          logInterop({ type: 'error', category: 'proof', message: msg, details: { code } });
          res.status(400).json({ error: code, error_description: msg });
          return;
        }
      }

      // Copies bound to the same key share cnf.jkt and would be linkable.
      if (new Set(holders.map(h => h.thumbprint)).size !== holders.length) {
        res.status(400).json({
          error: 'invalid_proof',
          error_description: 'Each proof in a batch must use a distinct holder key',
        });
        return;
      }
    } else if (isDemoMode) {
      // DEMO_MODE only: anonymous fallback — no holder binding
      console.warn('[issuer] DEMO_MODE: issuing credential without holder proof (no binding)');
      holders.push({ thumbprint: 'anonymous' });
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
    const credentialType = tokenEntry.credentialType ?? config.credential.type;
    try {
      template = getTemplate(credentialType);
    } catch (e) {
      res.status(500).json({ error: 'unsupported_credential_type', detail: (e as Error).message });
      return;
    }

    // A claims snapshot present on the token entry means this code went
    // through the consent gate: issue exactly what the holder reviewed
    // and approved, never recompute live (see token.ts's issuePreAuthCode).
    // Otherwise (the non-consent path, unchanged from before this existed)
    // compute claims live from the current config/mappings.
    let claims: Record<string, unknown>;
    if (tokenEntry.claims) {
      claims = tokenEntry.claims;
    } else {
      const { mappedData, errors: mappingErrors } = resolveMappedData(template, config.fieldMappings ?? {}, holderData);
      if (mappingErrors.length > 0) {
        logInterop({ type: 'warning', category: 'issuance', message: 'Field mapping failed', details: { errors: mappingErrors } });
        res.status(400).json({ error: 'invalid_field_mappings', detail: mappingErrors });
        return;
      }

      try {
        claims = template.buildClaims(mappedData, config.templateOptions);
      } catch (e) {
        console.error('[issuer] buildClaims error:', e);
        res.status(400).json({ error: 'claim_build_failed', detail: (e as Error).message });
        return;
      }
    }

    // ── Issue one copy per holder key ───────────────────────────────────────
    const format = config.credential.format ?? 'dc+sd-jwt';
    const holderEmail = String(holderData['email'] ?? holderData['id'] ?? 'unknown');
    // Issuer-side only: lets an admin revoke all copies at once. Never in the credential.
    const batchId = holders.length > 1 ? randomUUID() : undefined;

    // Timestamps rounded down to the UTC day: an exact issuance second would
    // be identical across batch copies and link them at the verifier.
    const DAY = 86400;
    const iat = Math.floor(Date.now() / 1000 / DAY) * DAY;
    const exp = iat + config.credential.expiresInDays * DAY;

    // Checked before any status index is consumed. A chain wallets would
    // reject stops issuance (Express 4 doesn't catch async throws).
    let identity: { iss: string; x5c?: string[] };
    try {
      identity = await getIssuerSigningIdentity(config);
    } catch (e) {
      console.error('[issuer]', (e as Error).message);
      res.status(500).json({ error: 'server_error', error_description: 'issuer certificate chain is invalid' });
      return;
    }

    const issued: Array<{ credential: string; credentialId: string; statusIndex: number }> = [];
    for (const holder of holders) {
      // Fresh salts per copy, so no disclosure or _sd digest repeats across copies.
      const { sdHashes, disclosures } = buildSdJwtPayload(claims);

      const credentialId = 'urn:uuid:' + randomUUID();
      const { listId, statusIndex } = assignStatusIndex(credentialId, holderEmail, batchId);

      // Pairwise pseudonym from this copy's key — differs per copy.
      const pseudonym = pairwisePseudonym(pseudonymSecret, holder.thumbprint, config.issuer.did, credentialType);

      /**
       * SD-JWT VC payload (draft-ietf-oauth-sd-jwt-vc):
       * - cnf.jkt: JWK thumbprint — binds this copy to one holder key
       * - _sd_alg, _sd: selective disclosure per IETF SD-JWT spec
       * - status.status_list: IETF Token Status List reference (random idx)
       * - No raw claim values in payload
       */
      const jwt = await new SignJWT({
        vct: credentialType,
        jti: credentialId,
        iss: identity.iss,
        sub: pseudonym,
        iat,
        exp,
        ...(holder.jwk ? { cnf: { jkt: holder.thumbprint } } : {}),
        _sd_alg: 'sha-256',
        _sd: sdHashes,
        status: {
          status_list: { idx: statusIndex, uri: `${config.issuer.url}/status/${listId}` },
        },
      })
        .setProtectedHeader({ alg: 'ES256', kid, typ: format, ...(identity.x5c ? { x5c: identity.x5c } : {}) })
        .sign(privateKey);

      issued.push({ credential: combineSdJwt(jwt, disclosures), credentialId, statusIndex });
    }

    // Rotate c_nonce after issuance (single-use; wallet can request more credentials with new nonce)
    const newNonce = rotateNonce(rawToken);

    console.log('[issuer] Issued ' + issued.length + 'x ' + credentialType
      + ' bound=' + (holders[0]?.jwk ? 'yes' : 'none')
      + (batchId ? ' batch=' + batchId : ''));

    const response: Record<string, unknown> = isBatch
      ? { credentials: issued.map(c => ({ credential: c.credential })) }
      : { credential: issued[0]!.credential, format };
    logInterop({
      type: 'info',
      category: 'issuance',
      message: `Issued ${issued.length}x ${credentialType}`,
      details: { credentialIds: issued.map(c => c.credentialId), holderEmail },
    });
    if (newNonce) {
      response['c_nonce'] = newNonce;
      response['c_nonce_expires_in'] = 300;
    }
    res.json(response);
  });

  return router;
}
