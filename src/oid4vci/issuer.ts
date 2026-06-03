import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { SignJWT } from 'jose';
import { createHmac, randomBytes, randomUUID } from 'crypto';
import { getIssuerKeyPair } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';
import { lookupAccessToken } from './token.js';
import { assignStatusIndex } from '../revocation/statuslist.js';

function pairwisePseudonym(secret: string, thumbprint: string, issuer: string, type: string): string {
  return 'did:askmi:pairwise:' + createHmac('sha256', secret)
    .update(`${thumbprint}|${issuer}|${type}`)
    .digest('base64url');
}

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

    // Map source fields → VC claims
    const claims: Record<string, unknown> = {};
    for (const [vcClaim, sourceField] of Object.entries(config.fieldMappings)) {
      if (holderData[sourceField] !== undefined) {
        claims[vcClaim] = holderData[sourceField];
      }
    }

    // Pairwise pseudonym
    const holderThumbprint = (req.body as Record<string, string>).proof_thumbprint ?? 'anonymous';
    const pseudonym = pairwisePseudonym(pseudonymSecret, holderThumbprint, config.issuer.did, config.credential.type);

    // Salted commitments
    const disclosures = Object.fromEntries(
      Object.entries(claims).map(([k, v]) => [k, saltedCommitment(v)])
    );

    // StatusList2021 — assign index and embed credentialStatus
    const credentialId = `urn:uuid:${randomUUID()}`;
    const holderEmail = String(holderData['email'] ?? holderData['id'] ?? 'unknown');
    const { listId, statusIndex } = assignStatusIndex(credentialId, holderEmail);

    const now = Math.floor(Date.now() / 1000);
    const exp = now + config.credential.expiresInDays * 86400;

    const jwt = await new SignJWT({
      vct: config.credential.type,
      jti: credentialId,
      iss: config.issuer.did,
      sub: pseudonym,
      iat: now,
      exp,
      credentialSubject: claims,
      _sd_disclosures: disclosures,
      credentialStatus: {
        id: `${config.issuer.url}/status/${listId}#${statusIndex}`,
        type: 'StatusList2021Entry',
        statusPurpose: 'revocation',
        statusListIndex: String(statusIndex),
        statusListCredential: `${config.issuer.url}/status/${listId}`,
      },
    })
      .setProtectedHeader({ alg: 'ES256', kid, typ: 'vc+sd-jwt' })
      .sign(privateKey);

    console.log(`[issuer] Issued credential ${credentialId} (status index: ${statusIndex})`);
    res.json({ credential: jwt, format: 'dc+sd-jwt' });
  });

  return router;
}
