import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { SignJWT } from 'jose';
import { createHmac, randomBytes } from 'crypto';
import { randomUUID } from 'crypto';
import { getIssuerKeyPair } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';
import { lookupAccessToken } from './token.js';
import { assignStatusIndex } from '../revocation/statuslist.js';
import { getTemplate } from '../credentials/registry.js';
import { buildSdJwtPayload, combineSdJwt } from '../sdjwt/disclosures.js';

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

    const token = auth.slice(7);
    const holderData = lookupAccessToken(token);
    if (!holderData) { res.status(401).json({ error: 'invalid_token' }); return; }

    const config = loadConfig();
    const { privateKey, kid } = await getIssuerKeyPair();

    // Resolve template — throws if type is unknown
    let template;
    try {
      template = getTemplate(config.credential.type);
    } catch (e) {
      console.error('[issuer] Unknown credential type:', config.credential.type);
      res.status(500).json({ error: 'unsupported_credential_type', detail: (e as Error).message });
      return;
    }

    // Validate field mappings
    const mappingErrors = template.validateMappings(config.fieldMappings);
    if (mappingErrors.length > 0) {
      console.error('[issuer] Field mapping errors:', mappingErrors);
      res.status(500).json({ error: 'invalid_field_mappings', detail: mappingErrors });
      return;
    }

    // Map source fields -> holderData keyed by template field names
    const mappedData: Record<string, unknown> = {};
    for (const [templateField, sourceField] of Object.entries(config.fieldMappings)) {
      if (holderData[sourceField] !== undefined) {
        mappedData[templateField] = holderData[sourceField];
      }
    }

    // Build claims via template (no raw PII leaks)
    let claims: Record<string, unknown>;
    try {
      claims = template.buildClaims(mappedData, config.templateOptions);
    } catch (e) {
      console.error('[issuer] buildClaims error:', e);
      res.status(400).json({ error: 'claim_build_failed', detail: (e as Error).message });
      return;
    }

    // Pairwise pseudonym
    // TODO: proof_thumbprint must be required outside DEMO_MODE (holder binding)
    const holderThumbprint = (req.body as Record<string, string>).proof_thumbprint ?? 'anonymous';
    const pseudonym = pairwisePseudonym(pseudonymSecret, holderThumbprint, config.issuer.did, config.credential.type);

    /**
     * SD-JWT-VC selective disclosure (IETF draft-ietf-oauth-selective-disclosure-jwt):
     *
     * All template claims become selective disclosures (Option A: minimization by construction).
     * - sdHashes: base64url(SHA-256(disclosure)) — go into _sd array in JWT payload
     * - disclosures: base64url(JSON.stringify([salt, name, value])) — appended after ~
     *
     * The holder receives the Combined Format and chooses which disclosures to present.
     * The verifier can confirm a claim by checking: hash(presented_disclosure) ∈ _sd.
     *
     * Structural claims (iss, iat, exp, vct, sub, jti, credentialStatus) stay top-level.
     */
    const { sdHashes, disclosures } = buildSdJwtPayload(claims);

    // StatusList2021
    const credentialId = 'urn:uuid:' + randomUUID();
    const holderEmail = String(holderData['email'] ?? holderData['id'] ?? 'unknown');
    const { listId, statusIndex } = assignStatusIndex(credentialId, holderEmail);

    const now = Math.floor(Date.now() / 1000);
    const exp = now + config.credential.expiresInDays * 86400;

    /**
     * SD-JWT-VC JWT payload (draft-ietf-oauth-sd-jwt-vc):
     * - vct: credential type identifier
     * - iss, iat, exp, sub, jti: standard JWT claims
     * - _sd_alg: hash algorithm used for selective disclosure digests
     * - _sd: array of base64url(SHA-256(disclosure)) — no raw claim values
     * - credentialStatus: StatusList2021 revocation entry
     *
     * Raw claim values are NOT in the payload.
     * They are carried in the disclosures appended after ~ in the Combined Format.
     */
    const jwt = await new SignJWT({
      vct: config.credential.type,
      jti: credentialId,
      iss: config.issuer.did,
      sub: pseudonym,
      iat: now,
      exp,
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

    // Combined Format: <issuer-signed-jwt>~<disclosure1>~<disclosure2>~
    const credential = combineSdJwt(jwt, disclosures);

    console.log('[issuer] Issued ' + config.credential.type + ' ' + credentialId
      + ' (' + disclosures.length + ' disclosures, status: ' + statusIndex + ')');
    res.json({ credential, format: 'dc+sd-jwt' });
  });

  return router;
}
