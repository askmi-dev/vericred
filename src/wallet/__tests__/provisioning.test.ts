import { registrarFixture } from '../../../tests/helpers/registrar-fixture.js';
import { beforeAll, beforeEach, afterEach, expect, it, vi } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { exportPKCS8, SignJWT } from 'jose';
import { getIssuerKeyPair } from '../../keys/manager.js';
import { inspectEudiMaterials } from '../provisioning.js';
import { attestationFixture } from '../../../tests/helpers/attestation-fixture.js';

const originalDir = process.env.DATA_DIR!;
let dir: string, certificatePath: string, keyPath: string, registrationPath: string;
let policy: Awaited<ReturnType<typeof attestationFixture>>;
let fetcher: ReturnType<typeof vi.fn>;
const config = {
  issuer: { name: 'Synthetic provisioning fixture', url: 'https://issuer.example.invalid', did: 'did:web:issuer.example.invalid' },
  credential: { type: 'AgeCredential', format: 'dc+sd-jwt', expiresInDays: 30 },
  dataSource: { type: 'manual' }, fieldMappings: { dateOfBirth: 'dateOfBirth' },
};
function snapshot(root: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    if (statSync(path).isDirectory()) {
      for (const [child, hash] of Object.entries(snapshot(path))) result[name + '/' + child] = hash;
    } else result[name] = createHash('sha256').update(readFileSync(path)).digest('hex');
  }
  return result;
}
beforeAll(async () => {
  dir = mkdtempSync(join(originalDir, 'offline-materials-')); process.env.DATA_DIR = dir;
  const keys = await getIssuerKeyPair();
  keyPath = join(dir, 'signer.pem'); certificatePath = join(dir, 'signer.crt');
  writeFileSync(keyPath, await exportPKCS8(keys.privateKey));
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  execFileSync(process.env.OPENSSL_BIN ?? (existsSync(bundled) ? bundled : 'openssl'),
    ['req', '-new', '-x509', '-key', keyPath, '-out', certificatePath, '-days', '2', '-subj', '/CN=synthetic-provisioning',
      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature'], { stdio: 'pipe', windowsHide: true });
  policy = await attestationFixture();
  const now = Math.floor(Date.now() / 1000);
  const registration = await new SignJWT({ sub: 'synthetic-registration', iat: now, exp: now + 3600,
    status: { status_list: { idx: 0, uri: 'https://registrar.example.invalid/status/one' } } })
    .setProtectedHeader({ alg: 'ES256', typ: 'rc-wrp+jwt', x5c: [policy.provider.certificate.raw.toString('base64')] })
    .sign(policy.provider.privateKey);
  registrationPath = join(dir, 'registration.jwt'); writeFileSync(registrationPath, registration);
});
beforeEach(() => {
  process.env.DATA_DIR = dir; process.env.WALLET_PROFILE = 'eudi-android';
  process.env.EUDI_REGISTRATION_POLICY = 'required';
  process.env.EUDI_ISSUER_CERT_CHAIN_PATH = certificatePath; process.env.EUDI_VERIFIER_CERT_CHAIN_PATH = certificatePath;
  process.env.EUDI_VERIFIER_KEY_PATH = keyPath;
  process.env.EUDI_ISSUER_REGISTRATION_CERT_PATH = registrationPath; process.env.EUDI_VERIFIER_REGISTRATION_CERT_PATH = registrationPath;
  for (const role of ['issuer', 'verifier'] as const) {
    const path = join(dir, role + '-registrar.json'); writeFileSync(path, JSON.stringify(registrarFixture(role)));
    process.env['EUDI_' + role.toUpperCase() + '_REGISTRAR_DATASET_PATH'] = path;
  }
  policy.provision(); writeFileSync(join(dir, 'vericred.config.json'), JSON.stringify(config));
  fetcher = vi.fn(() => { throw new Error('Offline preflight must never fetch'); }); vi.stubGlobal('fetch', fetcher);
});
afterEach(() => { expect(fetcher).not.toHaveBeenCalled(); vi.unstubAllGlobals(); process.env.DATA_DIR = originalDir; });
const find = (report: Awaited<ReturnType<typeof inspectEudiMaterials>>, id: string) => report.checks.find(check => check.id === id);

it('validates synthetic material without changing files, leaking secrets or accepting independent gates', async () => {
  const before = snapshot(dir); const report = await inspectEudiMaterials();
  expect(report).toMatchObject({ status: 'PASS', releaseAccepted: false, independentWalletAcceptance: 'NOT RUN',
    registrationPolicyOnAcceptance: 'NOT RUN', providerTrustAcceptance: 'NOT RUN', externalMaterialRecoveryAcceptance: 'NOT RUN' });
  expect(snapshot(dir)).toEqual(before);
  const serialized = JSON.stringify(report);
  for (const sensitive of [dir, process.env.ADMIN_API_KEY!, process.env.PSEUDO_SECRET!, readFileSync(keyPath, 'utf8'),
    readFileSync(registrationPath, 'utf8'), policy.provider.pin, policy.certification]) expect(serialized).not.toContain(sensitive);
});
it('does not create an absent data directory or default configuration', async () => {
  const missing = join(dir, 'absent-data'); process.env.DATA_DIR = missing;
  const report = await inspectEudiMaterials();
  expect(report.status).toBe('BLOCKED'); expect(find(report, 'existing_configuration')?.status).toBe('blocked');
  expect(existsSync(missing)).toBe(false);
});
it('does not initialize a configuration in an empty directory', async () => {
  const empty = mkdtempSync(join(dir, 'empty-')); process.env.DATA_DIR = empty;
  expect((await inspectEudiMaterials()).status).toBe('BLOCKED'); expect(readdirSync(empty)).toEqual([]);
});
it('does not generate a missing issuer key when inspecting an existing config', async () => {
  const empty = mkdtempSync(join(dir, 'no-keys-')); process.env.DATA_DIR = empty;
  writeFileSync(join(empty, 'vericred.config.json'), JSON.stringify(config));
  const before = snapshot(empty); const report = await inspectEudiMaterials();
  expect(find(report, 'issuer_certificate')?.status).toBe('blocked'); expect(snapshot(empty)).toEqual(before);
});
it('blocks a verifier certificate that does not match the supplied key', async () => {
  process.env.EUDI_VERIFIER_CERT_CHAIN_PATH = join(policy.dir, 'synthetic-status-provider.crt');
  const report = await inspectEudiMaterials();
  expect(report.status).toBe('BLOCKED'); expect(find(report, 'verifier_certificate')?.status).toBe('blocked');
});
it.each(['WALLET_PROFILE', 'EUDI_REGISTRATION_POLICY'])('requires the acceptance setting %s explicitly', async variable => {
  delete process.env[variable]; expect((await inspectEudiMaterials()).status).toBe('BLOCKED');
});
it('rejects missing deployment secrets without creating fallback secrets', async () => {
  const saved = process.env.PSEUDO_SECRET; delete process.env.PSEUDO_SECRET;
  try {
    const before = snapshot(dir); const report = await inspectEudiMaterials();
    expect(find(report, 'deployment_secrets')?.status).toBe('blocked'); expect(snapshot(dir)).toEqual(before);
  } finally { process.env.PSEUDO_SECRET = saved; }
});
it.each(['EUDI_WALLET_ATTESTATION_POLICY_PATH', 'EUDI_ISSUER_REGISTRATION_CERT_PATH', 'EUDI_ISSUER_REGISTRAR_DATASET_PATH', 'EUDI_VERIFIER_REGISTRAR_DATASET_PATH'])('blocks missing material %s', async variable => {
  process.env[variable] = join(dir, 'private-path-sentinel');
  const report = await inspectEudiMaterials(); expect(report.status).toBe('BLOCKED');
  expect(JSON.stringify(report)).not.toContain('private-path-sentinel');
});
