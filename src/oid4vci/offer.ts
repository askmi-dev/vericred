import { Router as createRouter } from 'express';
import type { Router, Request, Response } from 'express';
import { loadConfig } from '../config/loader.js';
import { issuePreAuthCode, buildCredentialOffer } from './token.js';
import type { Lookup } from '../connectors/index.js';
import { getTemplate } from '../credentials/registry.js';
import { resolveMappedData } from './issuer.js';
import { createConsentRecord, buildClaimsList } from './consent.js';

export function createOfferRouter(lookup: Lookup): Router {
  const router = createRouter();

  router.post('/offer', async (req: Request, res: Response) => {
    const { identifier, holderId, credentialType } = req.body as {
      identifier?: string;
      holderId?: string;
      credentialType?: string;
    };

    const targetIdentifier = holderId ?? identifier;
    if (!targetIdentifier) {
      res.status(400).json({ error: 'identifier or holderId required' });
      return;
    }

    const holderData = await Promise.resolve(lookup(targetIdentifier));
    if (!holderData) {
      res.status(404).json({ error: 'holder not found' });
      return;
    }

    const config = loadConfig();
    const resolvedType = credentialType ?? config.credential.type;

    let template;
    try {
      template = getTemplate(resolvedType);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
      return;
    }

    const { mappedData, errors: mappingErrors } = resolveMappedData(template, config.fieldMappings ?? {}, holderData);
    if (mappingErrors.length > 0) {
      res.status(400).json({ error: 'invalid_field_mappings', detail: mappingErrors });
      return;
    }

    if (template.requiresConsent) {
      let claims: Record<string, unknown>;
      try {
        claims = template.buildClaims(mappedData, config.templateOptions);
      } catch (e) {
        res.status(400).json({ error: 'claim_build_failed', detail: (e as Error).message });
        return;
      }
      const consentId = createConsentRecord(holderData, resolvedType, buildClaimsList(claims));
      res.json({ consent_required: true, consent_url: `${config.issuer.url}/consent/${consentId}` });
      return;
    }

    const code = issuePreAuthCode(holderData, resolvedType);
    res.json(buildCredentialOffer(code, resolvedType));
  });

  return router;
}
