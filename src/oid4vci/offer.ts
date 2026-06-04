import { Router as createRouter } from 'express';
import type { Router, Request, Response } from 'express';
import { loadConfig } from '../config/loader.js';
import { issuePreAuthCode } from './token.js';
import type { Lookup } from '../connectors/index.js';

export function createOfferRouter(lookup: Lookup): Router {
  const router = createRouter();

  router.post('/offer', async (req: Request, res: Response) => {
    const { identifier } = req.body as { identifier?: string };
    if (!identifier) { res.status(400).json({ error: 'identifier required' }); return; }

    const holderData = await Promise.resolve(lookup(identifier));
    if (!holderData) { res.status(404).json({ error: 'holder not found' }); return; }

    const config = loadConfig();
    const code = issuePreAuthCode(holderData);

    const offer = {
      credential_issuer: config.issuer.url,
      /**
       * credential_configuration_ids per OID4VCI draft-13+.
       * Older wallets may expect credential_type[] — adjust if wallet rejects this field.
       */
      credential_configuration_ids: [config.credential.type],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': code,
          /**
           * user_pin_required: false per OID4VCI draft-11 and earlier.
           * Draft-13+ uses tx_code instead. Keep for maximum compatibility;
           * remove if wallet rejects the field.
           */
          user_pin_required: false,
        },
      },
    };

    const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
    res.json({ offer, offer_uri: offerUri });
  });

  return router;
}
