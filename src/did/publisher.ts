/**
 * did:web publisher — serves /.well-known/did.json derived from the issuer public key.
 */
import { exportJWK } from 'jose';
import type { Router } from 'express';
import { Router as createRouter } from 'express';
import { getIssuerKeyPair } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';

export function createDidRouter(): Router {
  const router = createRouter();

  router.get('/.well-known/did.json', async (_req, res) => {
    const { publicKey, kid } = await getIssuerKeyPair();
    const config = loadConfig();
    const jwk = await exportJWK(publicKey);

    res.json({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: config.issuer.did,
      verificationMethod: [
        {
          id: `${config.issuer.did}#${kid}`,
          type: 'JsonWebKey2020',
          controller: config.issuer.did,
          publicKeyJwk: { ...jwk, kid },
        },
      ],
      assertionMethod: [`${config.issuer.did}#${kid}`],
    });
  });

  return router;
}
