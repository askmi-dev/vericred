import type { Router } from 'express';
import { Router as createRouter } from 'express';
import { loadConfig } from '../config/loader.js';

export function createMetadataRouter(): Router {
  const router = createRouter();

  router.get('/.well-known/openid-credential-issuer', (_req, res) => {
    const config = loadConfig();
    const base = config.issuer.url;

    res.json({
      issuer: base,
      credential_issuer: base,
      credential_endpoint: `${base}/credentials`,
      token_endpoint: `${base}/token`,
      display: [{ name: config.issuer.name }],
      credential_configurations_supported: {
        [config.credential.type]: {
          format: 'dc+sd-jwt',
          scope: config.credential.type,
          cryptographic_binding_methods_supported: ['jwk'],
          credential_signing_alg_values_supported: ['ES256'],
          display: [{ name: config.credential.type }],
        },
      },
    });
  });

  return router;
}
