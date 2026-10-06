import { Router as createRouter } from 'express';
import type { Router, Request, Response } from 'express';
import qrcode from 'qrcode';
import { loadConfig } from '../config/loader.js';
import { issuePreAuthCode, buildCredentialOffer } from './token.js';
import type { Lookup } from '../connectors/index.js';
import { getTemplate } from '../credentials/registry.js';
import { resolveMappedData } from './issuer.js';
import { createConsentRecord, buildClaimsList } from './consent.js';

/**
 * Renders a QR code for `uri` as a data: URL, server-side. The offer/
 * consent URI is a bearer capability (anyone holding it can redeem or
 * approve it), so it must never be handed to a third party just to draw
 * a QR image -- the previous console UI did exactly that by loading
 * https://api.qrserver.com/...?data=<uri> as an <img> src, which leaks
 * the capability to that third party's access logs. Generating the QR
 * locally keeps the URI entirely first-party.
 */
async function qrDataUrl(uri: string): Promise<string> {
  return qrcode.toDataURL(uri);
}

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
      const consentUrl = `${config.issuer.url}/consent/${consentId}`;
      res.json({ consent_required: true, consent_url: consentUrl, qr_data_url: await qrDataUrl(consentUrl) });
      return;
    }

    const code = issuePreAuthCode(holderData, resolvedType);
    const result = buildCredentialOffer(code, resolvedType);
    res.json({ ...result, qr_data_url: await qrDataUrl(result.offer_uri) });
  });

  return router;
}
