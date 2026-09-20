import { Router as createRouter } from 'express';
import type { Router, Request, Response } from 'express';
import qrcode from 'qrcode';
import { asyncHandler } from '../middleware/errors.js';
import { assertConfigUnchanged, ConfigConflictError, loadConfig } from '../config/loader.js';
import type { VeriCredConfig } from '../config/types.js';
import { resolveTemplateConfig } from '../config/template.js';
import { issuePreAuthCode } from './token.js';
import type { Lookup } from '../connectors/index.js';
import { getTemplate } from '../credentials/registry.js';
import { resolveMappedData } from './issuer.js';

export function createOfferRouter(lookup: Lookup, lookupForConfig?: (id: string, config: VeriCredConfig) => Promise<Record<string, unknown> | null>): Router {
  const router = createRouter();

  router.post('/offer', asyncHandler(async (req: Request, res: Response) => {
    const { identifier, holderId, credentialType } = (req.body ?? {}) as {
      identifier?: string;
      holderId?: string;
      credentialType?: string;
    };

    const targetIdentifier = holderId ?? identifier;
    if (typeof targetIdentifier !== 'string' || !targetIdentifier || targetIdentifier.length > 500) {
      res.status(400).json({ error: 'identifier or holderId required' });
      return;
    }

    const config = loadConfig();
    let holderData;
    try {
      holderData = await (lookupForConfig ? lookupForConfig(targetIdentifier, config) : Promise.resolve(lookup(targetIdentifier)));
      assertConfigUnchanged(config);
    } catch (error) {
      if (error instanceof ConfigConflictError || (error instanceof Error && error.name === 'ConnectorConfigChangedError')) {
        res.status(409).json({ error: 'configuration_changed', detail: 'Reload configuration and create a new offer.' }); return;
      }
      throw error;
    }
    if (!holderData) {
      res.status(404).json({ error: 'holder not found' });
      return;
    }

    const resolvedType = credentialType ?? config.credential.type;

    let template;
    try {
      template = getTemplate(resolvedType);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
      return;
    }

    const { fieldMappings, templateOptions } = resolveTemplateConfig(config, resolvedType);
    const optionErrors = template.validateOptions?.(templateOptions) ?? [];
    if (optionErrors.length) { res.status(400).json({ error: 'invalid_template_options', detail: optionErrors }); return; }
    const { errors: mappingErrors } = resolveMappedData(template, fieldMappings, holderData);
    if (mappingErrors.length > 0) {
      res.status(400).json({ error: 'invalid_field_mappings', detail: mappingErrors });
      return;
    }

    const code = issuePreAuthCode(holderData, resolvedType, config);

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
    res.setHeader('Cache-Control', 'no-store');
    res.json({ offer, offer_uri: offerUri, qr_code: await qrcode.toDataURL(offerUri) });
  }));

  return router;
}
