/**
 * Credential offer endpoint — generates a QR-ready offer link for a holder.
 */
import { Router as createRouter } from 'express';
import type { Router, Request, Response } from 'express';
import { loadConfig } from '../config/loader.js';
import { issuePreAuthCode } from './token.js';

export function createOfferRouter(
  lookup: (id: string) => Record<string, unknown> | null
): Router {
  const router = createRouter();

  // POST /offer { "identifier": "alice@example.com" }
  router.post('/offer', (req: Request, res: Response) => {
    const { identifier } = req.body as { identifier?: string };
    if (!identifier) { res.status(400).json({ error: 'identifier required' }); return; }

    const holderData = lookup(identifier);
    if (!holderData) { res.status(404).json({ error: 'holder not found' }); return; }

    const config = loadConfig();
    const code = issuePreAuthCode(holderData);

    const offer = {
      credential_issuer: config.issuer.url,
      credential_configuration_ids: [config.credential.type],
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
