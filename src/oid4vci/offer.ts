import { Router as createRouter } from 'express';
import type { Router, Request, Response } from 'express';
import { loadConfig } from '../config/loader.js';
import { issuePreAuthCode } from './token.js';
import type { Lookup } from '../connectors/index.js';
import { getTemplate } from '../credentials/registry.js';
import { resolveMappedData } from './issuer.js';

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

    const { errors: mappingErrors } = resolveMappedData(template, config.fieldMappings ?? {}, holderData);
    if (mappingErrors.length > 0) {
      res.status(400).json({ error: 'invalid_field_mappings', detail: mappingErrors });
      return;
    }

    const code = issuePreAuthCode(holderData, resolvedType);

    const offer = {
      credential_issuer: config.issuer.url,
      credential_configuration_ids: [resolvedType],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': code,
          user_pin_required: false,
        },
      },
    };

    const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
    res.json({ offer, offer_uri: offerUri });
  });

  return router;
}
