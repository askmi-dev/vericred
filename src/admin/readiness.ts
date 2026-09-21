import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey, sign, verify, X509Certificate, type KeyObject } from 'node:crypto';
import { loadConfig } from '../config/loader.js';
import { resolveTemplateConfig } from '../config/template.js';
import type { VeriCredConfig } from '../config/types.js';
import { credentialVct, getTemplate, listTemplates } from '../credentials/registry.js';
import { getWalletProfile, type WalletProfile } from '../wallet/profile.js';
import { inspectRegistration, inspectRegistrarDataset, registrationRequired } from '../wallet/registration.js';
import { inspectAttestationPolicy } from '../wallet/attestation.js';
import '../credentials/templates/age.js';
import '../credentials/templates/employee.js';
import '../credentials/templates/membership.js';

export interface ReadinessCheck {
  id: string;
  label: string;
  status: 'ready' | 'blocked' | 'not_verified' | 'not_applicable';
  basis: 'configuration' | 'local_validation' | 'independent_acceptance';
  detail: string;
}
interface CertificateReadiness { configured: boolean; valid: boolean | null; expiresAt: string | null; }

/** Pure local inspection: never generate keys, contact a trust service, or expose key/certificate paths. */
function inspectCertificate(role: 'issuer' | 'verifier', required: boolean): CertificateReadiness {
  const chainPath = process.env[role === 'issuer' ? 'EUDI_ISSUER_CERT_CHAIN_PATH' : 'EUDI_VERIFIER_CERT_CHAIN_PATH'];
  const keyPath = role === 'issuer' ? join(process.env.DATA_DIR ?? './keys', 'issuer-key.json') : process.env.EUDI_VERIFIER_KEY_PATH;
  const result: CertificateReadiness = { configured: Boolean(chainPath && keyPath), valid: null, expiresAt: null };
  if (!required || !result.configured) return result;
  result.valid = false;
  try {
    if (!keyPath || !existsSync(keyPath)) return result;
    const blocks = readFileSync(chainPath!, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
    if (!blocks?.length || blocks.length > 8) return result;
    const chain = blocks.map(block => new X509Certificate(block));
    const expiry = Math.min(...chain.map(cert => Date.parse(cert.validTo)));
    if (Number.isFinite(expiry)) result.expiresAt = new Date(expiry).toISOString();
    const now = Date.now();
    for (let index = 0; index < chain.length; index++) {
      if (now < Date.parse(chain[index].validFrom) || now >= Date.parse(chain[index].validTo)) return result;
      if (index + 1 < chain.length && (!chain[index + 1].ca || !chain[index].checkIssued(chain[index + 1]) ||
          !chain[index].verify(chain[index + 1].publicKey))) return result;
    }
    if (chain[0].ca) return result;
    let privateKey: KeyObject;
    const certified = chain[0].publicKey.export({ format: 'jwk' });
    if (role === 'issuer') {
      const stored = JSON.parse(readFileSync(keyPath, 'utf8'));
      if (!stored || typeof stored.kid !== 'string' || !stored.kid.trim() ||
          !stored.publicKey || stored.publicKey.kty !== 'EC' || stored.publicKey.crv !== 'P-256' ||
          ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(parameter => parameter in stored.publicKey)) return result;
      const published = createPublicKey({ key: stored.publicKey, format: 'jwk' }).export({ format: 'jwk' });
      if (published.x !== certified.x || published.y !== certified.y) return result;
      privateKey = createPrivateKey({ key: stored.privateKey, format: 'jwk' });
    } else privateKey = createPrivateKey(readFileSync(keyPath, 'utf8'));
    const signing = createPublicKey(privateKey).export({ format: 'jwk' });
    if (signing.kty !== 'EC' || signing.crv !== 'P-256' || signing.x !== certified.x || signing.y !== certified.y) return result;
    // Imported EC keys may retain supplied public coordinates even if their private scalar differs.
    // Prove this private key can sign for the certificate without invoking runtime key initialization.
    const challenge = Buffer.from('VeriCred readiness signing-key consistency v1\0' + role);
    result.valid = verify('sha256', challenge, chain[0].publicKey, sign('sha256', challenge, privateKey));
  } catch { /* Return a safe local-validation result without file paths or exception text. */ }
  return result;
}
function sourceConfigured(source: VeriCredConfig['dataSource']): boolean {
  switch (source.type) {
    case 'manual': return true;
    case 'json': case 'csv': return Boolean(source.path);
    case 'postgres': case 'mysql': return Boolean(source.connectionString);
    case 'rest': return Boolean(source.endpoint?.includes('{id}') && source.healthCheckIdentifier);
  }
}

/** Observes configuration and local signing material; independent acceptance evidence is never inferred. */
export async function getReadiness(config: VeriCredConfig = loadConfig()) {
  let walletProfile: WalletProfile | 'unsupported';
  try { walletProfile = getWalletProfile(); } catch { walletProfile = 'unsupported'; }
  const required = walletProfile === 'eudi-android';
  let walletAttestation = { configured: false, valid: false, providerCount: 0 };
  if (required) {
    try { walletAttestation = await inspectAttestationPolicy(); }
    catch { walletAttestation = { configured: Boolean(process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH), valid: false, providerCount: 0 }; }
  }
  let policyValid = true;
  let requiresRegistration = false;
  try { requiresRegistration = registrationRequired(); } catch { policyValid = false; }
  const absentRegistration: CertificateReadiness = { configured: false, valid: null, expiresAt: null };
  const inspect = async (role: 'issuer' | 'verifier'): Promise<CertificateReadiness> => {
    if (!required) return { ...absentRegistration };
    try { return await inspectRegistration(role); }
    catch { return { configured: true, valid: false, expiresAt: null }; }
  };
  const [issuerRegistration, verifierRegistration] = await Promise.all([inspect('issuer'), inspect('verifier')]);
  const registrations = { required: required && requiresRegistration, policyValid, issuer: issuerRegistration, verifier: verifierRegistration };
  const datasets = Object.fromEntries((['issuer', 'verifier'] as const).map(role => [role, required ? inspectRegistrarDataset(role) : { configured: false, valid: null }]));
  const certificates = { required, issuer: inspectCertificate('issuer', required), verifier: inspectCertificate('verifier', required) };
  const format = config.credential.format ?? 'dc+sd-jwt';
  const credentials = listTemplates().map(template => {
    const policy = resolveTemplateConfig(config, template.id);
    const implementation = getTemplate(template.id);
    const configured = implementation.validateMappings(policy.fieldMappings).length === 0 &&
      (implementation.validateOptions?.(policy.templateOptions).length ?? 0) === 0;
    return { type: template.id, format, vct: credentialVct(template.id), active: template.id === config.credential.type, configured };
  });
  const source = { type: config.dataSource.type, configured: sourceConfigured(config.dataSource) };
  const https = new URL(config.issuer.url).protocol === 'https:';
  const profileConfigured = walletProfile !== 'unsupported' && (!required || format === 'dc+sd-jwt');
  const checks: ReadinessCheck[] = [
    { id: 'https_configuration', label: 'HTTPS issuer configuration', status: https ? 'ready' : 'blocked', basis: 'configuration',
      detail: https ? 'The issuer URL uses HTTPS. Public reachability and TLS have not been tested here.' : 'Set an HTTPS issuer URL before a production release. This check does not contact that URL.' },
    { id: 'wallet_profile', label: 'Wallet profile configuration', status: profileConfigured ? 'ready' : 'blocked', basis: 'configuration',
      detail: !profileConfigured ? 'Select a supported wallet profile and credential format.' : required ? 'The EUDI Android protocol profile is configured. External trust and device acceptance remain unverified.' : 'The custom protocol profile is configured. Independent wallet acceptance remains unverified.' },
    { id: 'android_issuance_contract', label: 'Wallet key-attestation policy', status: !required ? 'not_applicable' : walletAttestation.valid ? 'ready' : 'blocked', basis: 'local_validation',
      detail: !required ? 'The custom profile does not inspect wallet key-attestation policy and is not evidence of pinned Android compatibility.' : walletAttestation.valid
        ? 'The configured wallet key-attestation policy passes local validation and supplies trusted-provider settings. Provider onboarding and independent Android key-attestation acceptance have not been established here.'
        : 'Android 2026.08.41 requires validated wallet key attestations. Configure a valid wallet-attestation policy with trusted-provider settings before issuance. Synthetic protocol tests do not establish device compatibility.' },
    ...(['issuer', 'verifier'] as const).map(role => ({
      id: role + '_certificate', label: (role === 'issuer' ? 'Issuer' : 'Verifier') + ' signing certificate',
      status: !required ? 'not_applicable' as const : certificates[role].valid === true ? 'ready' as const : 'blocked' as const,
      basis: 'local_validation' as const,
      detail: !required ? 'This profile does not require a signing certificate.' : certificates[role].valid === true
        ? 'Configured certificates are within their validity periods; the local P-256 signing material passes key-consistency and signature checks. External trust and registration have not been checked.'
        : 'Required certificate or signing material is missing, unreadable, expired, or inconsistent. Check the configured signing material; external trust is not assessed here.',
    })),
    { id: 'registration_policy', label: 'Registration policy', status: !policyValid ? 'blocked' : !required ? 'not_applicable' : 'ready', basis: 'configuration',
      detail: !policyValid ? 'Select a supported registration policy before continuing.' : !required ? 'Registration transport is not used by the custom profile.' : requiresRegistration
        ? 'Both issuer and verifier registration certificates are required. This setting does not establish wallet registration acceptance.'
        : 'Registration certificates are optional in this runtime. Registration-enabled wallet acceptance requires separately verified issuer and verifier registration.' },
    ...(['issuer', 'verifier'] as const).map(role => ({
      id: role + '_registration_transport', label: (role === 'issuer' ? 'Issuer' : 'Verifier') + ' registration transport',
      status: !required ? 'not_applicable' as const : registrations[role].valid === true ? 'ready' as const
        : registrations[role].configured || requiresRegistration || !policyValid ? 'blocked' as const : 'not_verified' as const,
      basis: 'local_validation' as const,
      detail: !required ? 'Registration transport is not used by the custom profile.' : registrations[role].valid === true
        ? 'The configured registration JWT passes local signature, time and structural checks. External trust, identity binding, registration status and scope have not been validated.'
        : registrations[role].configured ? 'The configured registration material did not pass local validation. Check the registration material; external acceptance remains unverified.'
        : requiresRegistration ? 'Required registration material is missing. Provide the registration certificate for this role.'
        : 'No registration material is configured. An optional policy does not prove registration-enabled wallet acceptance.',
    })),
    ...(['issuer', 'verifier'] as const).map(role => ({
      id: role + '_registrar_dataset', label: (role === 'issuer' ? 'Issuer' : 'Verifier') + ' registrar dataset',
      status: !required ? 'not_applicable' as const : datasets[role].valid ? 'ready' as const
        : datasets[role].configured || requiresRegistration || !policyValid ? 'blocked' as const : 'not_verified' as const,
      basis: 'local_validation' as const,
      detail: !required ? 'Registrar datasets are not used by the custom profile.' : datasets[role].valid
        ? 'The supplied dataset passes bounded local transport-shape checks. Registrar provenance, identity binding, nested scope semantics and live registration status remain unverified.'
        : 'Supply the role-specific registrar dataset. Required policy blocks missing material; configured invalid material always blocks. Do not derive registered data from local configuration.',
    })),
    { id: 'source_configuration', label: 'Source configuration', status: source.configured ? 'ready' : 'blocked', basis: 'configuration',
      detail: 'This check inspects source settings only. It does not open a connection, read holder records, or verify source availability.' },
    { id: 'credential_configuration', label: 'Active credential configuration', status: credentials.some(item => item.active && item.configured) ? 'ready' : 'blocked', basis: 'configuration',
      detail: 'The active template requires complete field mappings and valid template options. Holder data and resulting credentials have not been checked here.' },
    { id: 'recovery_policy', label: 'Recovery policy', status: 'ready', basis: 'configuration',
      detail: 'Offline recovery invalidates earlier sessions and grants, retires pre-recovery status lists, and requires credential reissuance. This is a policy description, not evidence of a restore drill.' },
    { id: 'public_https_acceptance', label: 'Public HTTPS acceptance', status: 'not_verified', basis: 'independent_acceptance',
      detail: 'No public HTTPS, proxy, or deployment acceptance evidence is evaluated by this endpoint.' },
    { id: 'wallet_acceptance', label: 'Independent wallet acceptance', status: 'not_verified', basis: 'independent_acceptance',
      detail: 'No independent EUDI reference-wallet or miTch device acceptance evidence is evaluated by this endpoint. Local protocol checks do not establish external trust or certification.' },
    { id: 'wallet_attestation_acceptance', label: 'Independent wallet key-attestation acceptance', status: 'not_verified', basis: 'independent_acceptance',
      detail: 'No independent wallet test or provider onboarding evidence is evaluated here. Local policy validation does not prove attestation-provider trust, wallet compatibility or end-to-end issuance acceptance.' },
    { id: 'registration_on_acceptance', label: 'Registration-enabled wallet acceptance', status: 'not_verified', basis: 'independent_acceptance',
      detail: 'No independent wallet test with registration enabled is evaluated here. External trust, issuer/verifier identity binding, registration status and authorized scope require separate acceptance evidence.' },
    { id: 'source_acceptance', label: 'Live source acceptance', status: 'not_verified', basis: 'independent_acceptance',
      detail: 'No live connector acceptance evidence is evaluated by this endpoint.' },
    { id: 'recovery_acceptance', label: 'Backup and restore acceptance', status: 'not_verified', basis: 'independent_acceptance',
      detail: 'No deployment backup and restore drill evidence is evaluated by this endpoint.' },
  ];
  return {
    generatedAt: new Date().toISOString(), issuer: { ...config.issuer }, walletProfile, source,
    credential: { type: config.credential.type, format, expiresInDays: config.credential.expiresInDays },
    credentials, certificates, registrations, datasets, walletAttestation, configurationReady: checks.every(check => check.status !== 'blocked'),
    releaseAccepted: false as const, checks,
  };
}
