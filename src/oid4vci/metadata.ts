import type { Router } from 'express';
import { Router as createRouter } from 'express';
import { loadConfig } from '../config/loader.js';
import { listTemplates, getTemplate } from '../credentials/registry.js';

// Templates must be registered before metadata is served
import '../credentials/templates/age.js';
import '../credentials/templates/employee.js';
import '../credentials/templates/membership.js';

/**
 * OID4VCI Issuer Metadata
 * draft-ietf-oauth-openid4vci — /.well-known/openid-credential-issuer
 *
 * credential_configurations_supported: one entry per registered template,
 * using the configured credential type as the credential_configuration_id.
 *
 * Wallets read this to know:
 *   - which credential types are available
 *   - which format to request (dc+sd-jwt)
 *   - which proof types and algorithms are supported
 *   - which binding methods are supported (jwk thumbprint)
 */
export function createMetadataRouter(): Router {
  const router = createRouter();

  router.get('/.well-known/openid-credential-issuer', (_req, res) => {
    const config = loadConfig();
    const base = config.issuer.url;

    // Build one credential_configuration per registered template.
    // Only the configured type is "active" (i.e. actually issuable right now),
    // but wallets see all supported types so they can request the right one.
    const credentialConfigurations: Record<string, unknown> = {};

    for (const t of listTemplates()) {
      credentialConfigurations[t.id] = {
        /**
         * Format identifier per OID4VCI draft-13+.
         * "dc+sd-jwt" = SD-JWT-based Verifiable Credential (draft-ietf-oauth-sd-jwt-vc).
         * Some wallets may still expect "vc+sd-jwt" (older drafts) — check your target wallet.
         */
        format: 'dc+sd-jwt',

        /**
         * Scope value a wallet can request at /token.
         * Matches credential_configuration_id by convention.
         */
        scope: t.id,

        /**
         * Binding methods: jwk = holder public key embedded in proof header.
         * Thumbprint bound via cnf.jkt claim in issued credential.
         */
        cryptographic_binding_methods_supported: ['jwk'],

        /** Signing algorithm used for the issuer JWT (ES256 / P-256). */
        credential_signing_alg_values_supported: ['ES256'],

        /**
         * Proof types supported for holder proof-of-possession.
         * proof_type: "jwt" with openid4vci-proof+jwt header typ.
         */
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256'],
          },
        },

        /** Claim names that will appear in the credential (via selective disclosure). */
        claims: Object.fromEntries(
          [...t.requiredFields, ...listTemplates().find(x => x.id === t.id)?.requiredFields ?? []].map(
            f => [f, { mandatory: t.requiredFields.includes(f) }]
          )
        ),

        display: [
          {
            name: (() => {
              try { return getTemplate(t.id).displayName; } catch { return t.id; }
            })(),
            locale: 'en',
          },
        ],
      };
    }

    res.json({
      issuer: base,
      credential_issuer: base,
      credential_endpoint: `${base}/credentials`,
      token_endpoint: `${base}/token`,

      display: [
        { name: config.issuer.name, locale: 'en' },
      ],

      credential_configurations_supported: credentialConfigurations,
    });
  });

  return router;
}
