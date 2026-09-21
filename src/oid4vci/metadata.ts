import { attestationRequirements } from '../wallet/attestation.js';
import { registrationInfo } from '../wallet/registration.js';
import { Router } from 'express';
import { SignJWT } from 'jose';
import { resolveTemplateConfig } from '../config/template.js';
import { certificateSigner, getWalletProfile } from '../wallet/profile.js';
import { issuerEncryptionKey, encryptionAlgorithm, encryptionMethods } from '../wallet/encryption.js';
import { loadConfig } from '../config/loader.js';
import { credentialVct, getTemplate, listTemplates } from '../credentials/registry.js';
import { getAllPublicKeys } from '../keys/manager.js';
import { asyncHandler } from '../middleware/errors.js';
import '../credentials/templates/age.js';
import '../credentials/templates/employee.js';
import '../credentials/templates/membership.js';

/** Advertise emitted claims, never raw source fields such as dateOfBirth. */
function claimsFor(type: string, mappings: Record<string, string>, options: Record<string, unknown>) {
  if (type === 'AgeCredential') {
    const thresholds = Array.isArray(options.ageThresholds) ? options.ageThresholds : [18, 21];
    return [...thresholds.map(t => 'age_over_' + t), 'age_attested_at',
      ...(options.jurisdiction || mappings.jurisdiction ? ['jurisdiction'] : [])];
  }
  const required = type === 'EmployeeCredential'
    ? ['given_name', 'family_name', 'organization', 'role', 'valid_until']
    : ['organization', 'membership_type'];
  const optional = type === 'EmployeeCredential'
    ? { department: 'department', employeeId: 'employee_id' }
    : { memberId: 'member_id', memberSince: 'member_since', memberUntil: 'member_until', given_name: 'given_name', family_name: 'family_name' };
  return [...required, ...Object.entries(optional).filter(([source]) => mappings[source]).map(([, claim]) => claim),
    ...(type === 'MembershipCredential' && options.memberUntil && !mappings.memberUntil ? ['member_until'] : [])];
}

export function createMetadataRouter(): Router {
  const router = Router();
  router.get('/.well-known/openid-credential-issuer', asyncHandler(async (req, res) => {
    const config = loadConfig();
    const base = config.issuer.url;
    const configurations: Record<string, unknown> = {};
    for (const template of listTemplates()) {
      const { fieldMappings: mappings, templateOptions: options } = resolveTemplateConfig(config, template.id);
      if (getTemplate(template.id).validateMappings(mappings).length) continue;
      configurations[template.id] = {
        format: config.credential.format ?? 'dc+sd-jwt',
        vct: credentialVct(template.id), scope: template.id,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'],
          ...(getWalletProfile() === 'eudi-android' ? { key_attestations_required: attestationRequirements(config.credential.expiresInDays * 86400) } : {}) } },
        credential_metadata: {
          display: [{ name: template.displayName, locale: 'en' }],
          claims: claimsFor(template.id, mappings, options).map(name => ({ path: [name], display: [{ name, locale: 'en' }] })),
        },
      };
    }
    const metadata = {
      credential_issuer: base, authorization_servers: [base],
      credential_endpoint: base + '/credentials', nonce_endpoint: base + '/nonce',
      // Retained discovery extension for draft clients.
      token_endpoint: base + '/token',
      display: [{ name: config.issuer.name, locale: 'en' }],
      credential_configurations_supported: configurations,
      ...(getWalletProfile() === 'eudi-android' ? {
        issuer_info: await registrationInfo('issuer'),
        credential_request_encryption: { jwks: { keys: [(await issuerEncryptionKey()).publicKey] },
          enc_values_supported: encryptionMethods, encryption_required: true },
        credential_response_encryption: { alg_values_supported: [encryptionAlgorithm],
          enc_values_supported: encryptionMethods, encryption_required: true },
      } : {}),
    };
    res.vary('Accept');
    res.setHeader('Cache-Control', 'no-store');
    if (getWalletProfile() === 'eudi-android') {
      const signer = await certificateSigner('issuer');
      if (req.accepts(['application/jwt', 'application/json']) === 'application/jwt') {
        const jwt = await new SignJWT(metadata).setProtectedHeader({ alg: 'ES256', typ: 'openidvci-issuer-metadata+jwt', x5c: signer.x5c })
          .setIssuer(base).setSubject(base).setIssuedAt().setExpirationTime('5m').sign(signer.privateKey);
        res.type('application/jwt').send(jwt); return;
      }
    }
    res.json(metadata);
  }));
  router.get('/.well-known/oauth-authorization-server', (_req, res) => {
    const base = loadConfig().issuer.url;
    res.json({
      issuer: base, token_endpoint: base + '/token', jwks_uri: base + '/.well-known/jwks.json',
      grant_types_supported: ['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
      response_types_supported: [], token_endpoint_auth_methods_supported: ['none'],
      'pre-authorized_grant_anonymous_access_supported': true,
    });
  });
  router.get('/.well-known/jwks.json', asyncHandler(async (_req, res) => {
    res.json({ keys: (await getAllPublicKeys()).map(k => ({ ...k.publicKey, kid: k.kid, use: 'sig', alg: 'ES256' })) });
  }));
  return router;
}
