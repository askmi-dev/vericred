import { readFileSync, statSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { validateConfig } from '../config/validate.js';
import { issuerUrlToDidWeb } from '../config/loader.js';
import { getReadiness, type ReadinessCheck } from '../admin/readiness.js';

const materialChecks = new Set(['https_configuration', 'wallet_profile', 'android_issuance_contract',
  'issuer_certificate', 'verifier_certificate', 'registration_policy', 'issuer_registration_transport',
  'verifier_registration_transport', 'issuer_registrar_dataset', 'verifier_registrar_dataset', 'credential_configuration']);

/** Read existing files only. Never initialize config/keys, load .env, connect to sources or fetch status. */
export async function inspectEudiMaterials() {
  const checks: ReadinessCheck[] = [];
  const check = (id: string, label: string, ready: boolean, detail: string) => checks.push({
    id, label, status: ready ? 'ready' : 'blocked', basis: 'configuration', detail,
  });
  check('eudi_profile_required', 'EUDI profile selected', process.env.WALLET_PROFILE === 'eudi-android',
    'This preflight requires WALLET_PROFILE=eudi-android. A custom-profile pass is not EUDI evidence.');
  check('registration_required', 'Required registration policy selected', process.env.EUDI_REGISTRATION_POLICY === 'required',
    'This preflight requires EUDI_REGISTRATION_POLICY=required; it does not change the wallet setting.');
  check('deployment_secrets', 'Deployment secrets supplied',
    [process.env.ADMIN_API_KEY, process.env.PSEUDO_SECRET].every(value => typeof value === 'string' && value.length >= 32),
    'Supply both deployment secrets through the environment, each at least 32 characters. Presence and length do not prove randomness or recovery continuity.');
  try {
    const dataDir = process.env.DATA_DIR;
    if (!dataDir || !isAbsolute(dataDir) || !statSync(dataDir).isDirectory()) throw new Error();
    const configPath = join(dataDir, 'vericred.config.json');
    const stat = statSync(configPath);
    if (!stat.isFile() || stat.size > 1024 * 1024) throw new Error();
    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    if (process.env.ISSUER_URL) {
      config.issuer.url = process.env.ISSUER_URL;
      config.issuer.did = issuerUrlToDidWeb(process.env.ISSUER_URL);
    }
    const validated = validateConfig({ ...config, revision: config.revision ?? 0 });
    check('existing_configuration', 'Existing issuer configuration', true,
      'An existing configuration was read. No issuer data or keys were initialized.');
    // Supply the already-read configuration so readiness cannot create a default one.
    const readiness = await getReadiness(validated);
    checks.push(...readiness.checks.filter(item => materialChecks.has(item.id)));
  } catch {
    check('existing_configuration', 'Existing issuer configuration', false,
      'Set an absolute DATA_DIR containing a readable, valid vericred.config.json. No default configuration is generated.');
  }
  return {
    status: checks.every(item => item.status === 'ready') ? 'PASS' as const : 'BLOCKED' as const,
    scope: 'Offline EUDI material and configuration consistency only', generatedAt: new Date().toISOString(),
    checks, releaseAccepted: false,
    independentWalletAcceptance: 'NOT RUN', registrationPolicyOnAcceptance: 'NOT RUN',
    providerTrustAcceptance: 'NOT RUN', publicHttpsAcceptance: 'NOT RUN',
    liveSourceAcceptance: 'NOT RUN', externalMaterialRecoveryAcceptance: 'NOT RUN',
  };
}
