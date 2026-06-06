/**
 * did:web publisher — serves /.well-known/did.json derived from the issuer public key.
 */
import { Router as createRouter, type Router } from 'express';
import { getAllPublicKeys } from '../keys/manager.js';
import { loadConfig } from '../config/loader.js';

export function createDidRouter(): Router {
  const router = createRouter();

  router.get('/.well-known/did.json', async (_req, res) => {
    const allKeys = await getAllPublicKeys();
    const config = loadConfig();

    const verificationMethod = allKeys.map(k => ({
      id: `${config.issuer.did}#${k.kid}`,
      type: 'JsonWebKey2020',
      controller: config.issuer.did,
      publicKeyJwk: { ...k.publicKey, kid: k.kid },
    }));

    res.json({
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: config.issuer.did,
      verificationMethod,
      assertionMethod: verificationMethod.map(m => m.id),
      authentication: verificationMethod.map(m => m.id),
    });
  });

  return router;
}
