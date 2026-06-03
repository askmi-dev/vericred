import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { SignJWT } from 'jose';
import { createHmac, randomBytes, randomUUID } from 'crypto';
import { getIssuerKeyPair } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';
import { lookupAccessToken } from './token.js';
import { assignStatusIndex } from '../revocation/statuslist.js';
import { getTemplate } from '../credentials/registry.js';

// Register all built-in templates
import '../credentials/templates/age.js';
import '../credentials/templates/employee.js';
import '../credentials/templates/membership.js';

function pairwisePseudonym(secret: string, thumbprint: string, issuer: string, type: string): string {
  return 'did:askmi:pairwise:' + createHmac('sha256', secret)
    .update(thumbprint + '|' + issuer + '|' + type)
    .digest('base64url');
}

/**
 * SD-JWT-VC disclosure model (simplified / non-interoperable with external wallets).
 *
 * Each claim value is hashed with a random salt using HMAC-SHA256.
 * The commitment is stored alongside the salt so the holder can prove knowledge
 * of the original value without revealing it directly.
 *
 * NOTE: This is NOT the IETF SD-JWT disclosure format (draft-ietf-oauth-selective-disclosure-jwt).
 * For wallet interop, replace with: base64url(JSON.stringify([salt, claimName, claimValue]))
 * and include the raw disclosures appended to the JWT as: <jwt>~<d1>~<d2>~
 * Tracked as: TODO interop-sd-jwt-disclosure-format
 */
function saltedCommitment(value: unknown): { salt: string; commitment: string } {
  const salt = randomBytes(16).toString('hex');
  const commitment = createHmac('sha256', salt).update(String(value)).digest('base64url');
  return { salt, commitment };
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
    // TODO: proof_thumbprint should be required for production; anonymous fallback only in DEMO_MODE
    const holderThumbprint = (req.body as Record<string, string>).proof_thumbprint ?? 'anonymous';
    const pseudonym = pairwisePseudonym(pseudonymSecret, holderThumbprint, config.issuer.did, config.credential.type);

    // Simplified salted commitments (non-standard, see comment on saltedCommitment)
    const sdDisclosures = Object.fromEntries(
      Object.entries(claims).map(([k, v]) => [k, saltedCommitment(v)])
    );

    // StatusList2021
    const credentialId = 'urn:uuid:' + randomUUID();
    const holderEmail = String(holderData['email'] ?? holderData['id'] ?? 'unknown');
    const { listId, statusIndex } = assignStatusIndex(credentialId, holderEmail);

    const now = Math.floor(Date.now() / 1000);
    const exp = now + config.credential.expiresInDays * 86400;

    /**
     * SD-JWT-VC payload (draft-ietf-oauth-sd-jwt-vc):
     * - vct: credential type identifier
     * - iss, iat, exp, sub: standard JWT claims
     * - jti: unique credential identifier
     * - claims spread at top level (NOT nested under credentialSubject — that is W3C VC-JWT, not SD-JWT-VC)
     * - _sd_alg: hash algorithm for selective disclosure
     * - _sd_disclosures: simplified commitment map (non-standard — see TODO above)
     * - credentialStatus: StatusList2021 revocation entry
     */
    const jwt = await new SignJWT({
      vct: config.credential.type,
      jti: credentialId,
      iss: config.issuer.did,
      sub: pseudonym,
      iat: now,
      exp,
      // Claims at top level per SD-JWT-VC spec (not nested under credentialSubject)
      ...claims,
      _sd_alg: 'sha-256',
      _sd_disclosures: sdDisclosures,
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

    console.log('[issuer] Issued ' + config.credential.type + ' ' + credentialId + ' (status: ' + statusIndex + ')');
    res.json({ credential: jwt, format: 'dc+sd-jwt' });
  });

  return router;
}
