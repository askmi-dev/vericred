import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import type { Server } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createPrivateKey, createPublicKey, sign, verify, X509Certificate } from 'node:crypto';
import { exportJWK, exportPKCS8, generateKeyPair, type JWK } from 'jose';
import { createAdminRouter } from '../router.js';
import { getReadiness } from '../readiness.js';
import * as registration from '../../wallet/registration.js';
import * as attestation from '../../wallet/attestation.js';
import { configPath, DEFAULT_CONFIG, loadConfig, saveConfig } from '../../config/loader.js';

const baseDataDir = process.env.DATA_DIR!;
const envNames = ['WALLET_PROFILE', 'EUDI_ISSUER_CERT_CHAIN_PATH', 'EUDI_VERIFIER_CERT_CHAIN_PATH', 'EUDI_VERIFIER_KEY_PATH', 'EUDI_REGISTRATION_POLICY', 'EUDI_ISSUER_REGISTRATION_CERT_PATH', 'EUDI_VERIFIER_REGISTRATION_CERT_PATH', 'EUDI_WALLET_ATTESTATION_POLICY_PATH'] as const;
const initialEnv = Object.fromEntries(envNames.map(name => [name, process.env[name]]));
const sourceSecret = 'readiness-secret-must-not-leak';
const sourceIdentifier = 'readiness-person-must-not-leak';
let certPath: string;
let keyPath: string;
let privateJwk: JWK;
let publicJwk: JWK;
let otherPrivateJwk: JWK;
let otherPublicJwk: JWK;
let expiry: number;
let chainPaths: { valid: string; nonCa: string; unrelated: string };
let server: Server | undefined;
const connector = {
  lookup: vi.fn(() => { throw new Error('Readiness must not look up a holder'); }),
  getSchema: vi.fn(() => { throw new Error('Readiness must not read a source schema'); }),
  healthCheck: vi.fn(() => { throw new Error('Readiness must not probe a source'); }),
  list: vi.fn(() => { throw new Error('Readiness must not list holders'); }),
};

async function request(authenticated = true) {
  const app = express();
  app.use(createAdminRouter(connector));
  server = await new Promise<Server>(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
  const address = server.address() as { port: number };
  return fetch('http://127.0.0.1:' + address.port + '/admin/api/readiness', {
    headers: authenticated ? { Authorization: 'Bearer ' + process.env.ADMIN_API_KEY } : {},
  });
}
function configureCertificates(withIssuerKey = true) {
  process.env.WALLET_PROFILE = 'eudi-android';
  process.env.EUDI_ISSUER_CERT_CHAIN_PATH = certPath;
  process.env.EUDI_VERIFIER_CERT_CHAIN_PATH = certPath;
  process.env.EUDI_VERIFIER_KEY_PATH = keyPath;
  if (withIssuerKey) writeFileSync(join(process.env.DATA_DIR!, 'issuer-key.json'), JSON.stringify({ kid: 'readiness-fixture', publicKey: publicJwk, privateKey: privateJwk }));
}
const check = (readiness: Awaited<ReturnType<typeof getReadiness>>, id: string) => readiness.checks.find(item => item.id === id)!;

beforeAll(async () => {
  const dir = mkdtempSync(join(baseDataDir, 'readiness-certificate-'));
  keyPath = join(dir, 'private-signing.pem'); certPath = join(dir, 'signing.crt');
  const pair = await generateKeyPair('ES256', { extractable: true });
  privateJwk = await exportJWK(pair.privateKey); publicJwk = await exportJWK(pair.publicKey);
  writeFileSync(keyPath, await exportPKCS8(pair.privateKey), { mode: 0o600 });
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  const openssl = process.env.OPENSSL_BIN ?? (existsSync(bundled) ? bundled : 'openssl');
  execFileSync(openssl, ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '2',
    '-subj', '/CN=readiness.example.invalid', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature'], { stdio: 'pipe', windowsHide: true });
  expiry = Date.parse(new X509Certificate(readFileSync(certPath)).validTo);
  const parentKeyPath = join(dir, 'parent-key.pem');
  const parentPair = await generateKeyPair('ES256', { extractable: true });
  otherPrivateJwk = await exportJWK(parentPair.privateKey); otherPublicJwk = await exportJWK(parentPair.publicKey);
  writeFileSync(parentKeyPath, await exportPKCS8(parentPair.privateKey), { mode: 0o600 });
  const parents = { valid: join(dir, 'parent.crt'), nonCa: join(dir, 'non-ca-parent.crt'), unrelated: join(dir, 'unrelated-parent.crt') };
  for (const [kind, path] of Object.entries(parents)) {
    execFileSync(openssl, ['req', '-new', '-x509', '-key', parentKeyPath, '-out', path, '-days', '2',
      '-subj', '/CN=' + (kind === 'unrelated' ? 'unrelated-parent.example.invalid' : 'readiness-parent.example.invalid'),
      '-addext', 'basicConstraints=critical,CA:' + (kind === 'nonCa' ? 'FALSE' : 'TRUE'),
      '-addext', 'keyUsage=critical,' + (kind === 'nonCa' ? 'digitalSignature' : 'keyCertSign,cRLSign')],
    { stdio: 'pipe', windowsHide: true });
  }
  const requestPath = join(dir, 'leaf.csr');
  const leafPath = join(dir, 'leaf.crt');
  const extensionsPath = join(dir, 'leaf.ext');
  writeFileSync(extensionsPath, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
  execFileSync(openssl, ['req', '-new', '-key', keyPath, '-out', requestPath, '-subj', '/CN=readiness.example.invalid'],
    { stdio: 'pipe', windowsHide: true });
  execFileSync(openssl, ['x509', '-req', '-in', requestPath, '-CA', parents.valid, '-CAkey', parentKeyPath,
    '-set_serial', '42', '-days', '2', '-out', leafPath, '-extfile', extensionsPath], { stdio: 'pipe', windowsHide: true });
  const leafPem = readFileSync(leafPath, 'utf8');
  const leaf = new X509Certificate(leafPem);
  chainPaths = { valid: join(dir, 'valid-chain.pem'), nonCa: join(dir, 'non-ca-chain.pem'), unrelated: join(dir, 'unrelated-chain.pem') };
  for (const kind of ['valid', 'nonCa', 'unrelated'] as const) {
    const parentPem = readFileSync(parents[kind], 'utf8');
    // Each parent has the signing key: signature-only validation would accept every chain.
    expect(leaf.verify(new X509Certificate(parentPem).publicKey)).toBe(true);
    writeFileSync(chainPaths[kind], leafPem + '\n' + parentPem);
  }
  expect(leaf.checkIssued(new X509Certificate(readFileSync(parents.valid)))).toBe(true);
  expect(leaf.checkIssued(new X509Certificate(readFileSync(parents.unrelated)))).toBe(false);
});
beforeEach(() => {
  process.env.DATA_DIR = mkdtempSync(join(baseDataDir, 'readiness-case-'));
  for (const name of envNames) delete process.env[name];
  process.env.WALLET_PROFILE = 'custom';
  vi.spyOn(attestation, 'inspectAttestationPolicy').mockReturnValue({ configured: false, valid: false, providerCount: 0 });
  for (const method of Object.values(connector)) method.mockClear();
  saveConfig({ ...structuredClone(DEFAULT_CONFIG),
    issuer: { name: 'Readiness fixture', url: 'https://readiness.example.invalid', did: 'did:web:readiness.example.invalid' },
    dataSource: { type: 'rest', endpoint: 'https://private-source.example.invalid/holders/{id}', authHeader: 'Bearer ' + sourceSecret, healthCheckIdentifier: sourceIdentifier },
  });
});
afterEach(async () => {
  if (server) await new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve()));
  server = undefined;
  vi.restoreAllMocks();
  process.env.DATA_DIR = baseDataDir;
  for (const name of envNames) { if (initialEnv[name] === undefined) delete process.env[name]; else process.env[name] = initialEnv[name]; }
});

describe('Authenticated, observational admin readiness', async () => {
  it('rejects unauthenticated access', async () => {
    const response = await request(false);
    expect(response.status).toBe(401);
    expect(await response.text()).not.toContain('Readiness fixture');
  });

  it('reports safe observed configuration without reading holder data or probing the source', async () => {
    const before = readdirSync(process.env.DATA_DIR!);
    const response = await request();
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json();
    expect(body.issuer).toEqual({ name: 'Readiness fixture', url: 'https://readiness.example.invalid', did: 'did:web:readiness.example.invalid' });
    expect(body.source).toEqual({ type: 'rest', configured: true });
    expect(body.credential).toEqual({ type: 'AgeCredential', format: 'dc+sd-jwt', expiresInDays: 30 });
    expect(body.credentials).toContainEqual({ type: 'AgeCredential', format: 'dc+sd-jwt', vct: 'urn:vericred:credential:AgeCredential:1', active: true, configured: true });
    expect(Number.isFinite(Date.parse(body.generatedAt))).toBe(true);
    expect(body.configurationReady).toBe(true);
    expect(body.releaseAccepted).toBe(false);
    const serialized = JSON.stringify(body);
    for (const secret of [sourceSecret, sourceIdentifier, process.env.ADMIN_API_KEY!, process.env.PSEUDO_SECRET!, 'private-source.example.invalid', process.env.DATA_DIR!, 'fieldMappings', 'connectionString', 'authHeader']) expect(serialized).not.toContain(secret);
    for (const method of Object.values(connector)) expect(method).not.toHaveBeenCalled();
    expect(readdirSync(process.env.DATA_DIR!)).toEqual(before);
  });

  it('keeps deployment, wallet, source and recovery acceptance unverified even when configuration is ready', async () => {
    const body = await getReadiness();
    expect(body.configurationReady).toBe(true);
    expect(body.releaseAccepted).toBe(false);
    const external = body.checks.filter(item => item.basis === 'independent_acceptance');
    expect(external.map(item => item.id)).toEqual(['public_https_acceptance', 'wallet_acceptance', 'wallet_attestation_acceptance', 'registration_on_acceptance', 'source_acceptance', 'recovery_acceptance']);
    expect(external.every(item => item.status === 'not_verified')).toBe(true);
    expect(check(body, 'recovery_policy')).toMatchObject({ status: 'ready', basis: 'configuration' });
    expect(check(body, 'issuer_certificate').status).toBe('not_applicable');
    expect(body.certificates.issuer.valid).toBeNull();
  });

  it('blocks HTTP configuration without claiming to test public TLS', async () => {
    const config = loadConfig(); config.issuer.url = 'http://readiness.example.invalid'; saveConfig(config);
    const body = await getReadiness();
    expect(check(body, 'https_configuration')).toMatchObject({ status: 'blocked', basis: 'configuration' });
    expect(body.configurationReady).toBe(false);
    expect(check(body, 'public_https_acceptance').status).toBe('not_verified');
  });

  it('blocks unsupported profile settings without exposing the environment value', async () => {
    process.env.WALLET_PROFILE = 'private-invalid-profile-sentinel';
    const body = await getReadiness();
    expect(body.walletProfile).toBe('unsupported');
    expect(check(body, 'wallet_profile').status).toBe('blocked');
    expect(body.configurationReady).toBe(false);
    expect(JSON.stringify(body)).not.toContain('private-invalid-profile-sentinel');
  });

  it('reports missing EUDI certificates without generating signing material', async () => {
    process.env.WALLET_PROFILE = 'eudi-android';
    const body = await getReadiness();
    expect(body.certificates).toEqual({ required: true, issuer: { configured: false, valid: null, expiresAt: null }, verifier: { configured: false, valid: null, expiresAt: null } });
    expect(check(body, 'issuer_certificate').status).toBe('blocked');
    expect(check(body, 'verifier_certificate').status).toBe('blocked');
    expect(body.configurationReady).toBe(false);
    expect(existsSync(join(process.env.DATA_DIR!, 'issuer-key.json'))).toBe(false);
  });

  it('accepts matching, locally valid signing material while leaving external trust and wallet acceptance unknown', async () => {
    configureCertificates();
    const body = await getReadiness();
    expect(body.certificates.issuer).toEqual({ configured: true, valid: true, expiresAt: new Date(expiry).toISOString() });
    expect(body.certificates.verifier).toEqual(body.certificates.issuer);
    expect(body.configurationReady).toBe(false);
    expect(check(body, 'android_issuance_contract').status).toBe('blocked');
    expect(check(body, 'issuer_certificate')).toMatchObject({ status: 'ready', basis: 'local_validation' });
    expect(check(body, 'wallet_acceptance').status).toBe('not_verified');
    expect(body.releaseAccepted).toBe(false);
    const serialized = JSON.stringify(body);
    for (const value of [certPath, keyPath, privateJwk.d!, 'BEGIN CERTIFICATE', 'privateKey']) expect(serialized).not.toContain(value);
  });

  it.each(['missing_public_key', 'mismatched_public_key', 'private_public_key', 'missing_kid', 'empty_kid', 'invalid_kid'])
    ('blocks incomplete or inconsistent stored issuer material: %s', async failure => {
      configureCertificates();
      const issuerPath = join(process.env.DATA_DIR!, 'issuer-key.json');
      const stored = JSON.parse(readFileSync(issuerPath, 'utf8'));
      if (failure === 'missing_public_key') delete stored.publicKey;
      else if (failure === 'mismatched_public_key') stored.publicKey = otherPublicJwk;
      else if (failure === 'private_public_key') stored.publicKey = privateJwk;
      else if (failure === 'missing_kid') delete stored.kid;
      else if (failure === 'empty_kid') stored.kid = '   ';
      else stored.kid = 42;
      writeFileSync(issuerPath, JSON.stringify(stored));
      const before = readFileSync(issuerPath);
      const filesBefore = readdirSync(process.env.DATA_DIR!);
      const network = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Readiness must remain offline'));
      const body = await getReadiness();
      expect(check(body, 'issuer_certificate').status).toBe('blocked');
      expect(body.certificates.issuer.valid).toBe(false);
      expect(body.certificates.verifier.valid).toBe(true);
      expect(body.configurationReady).toBe(false);
      expect(body.releaseAccepted).toBe(false);
      expect(readFileSync(issuerPath)).toEqual(before);
      expect(readdirSync(process.env.DATA_DIR!)).toEqual(filesBefore);
      expect(network).not.toHaveBeenCalled();
      const serialized = JSON.stringify(body);
      for (const value of [issuerPath, privateJwk.d!, 'readiness-fixture']) expect(serialized).not.toContain(value);
    });

  it.each(['issuer', 'verifier'] as const)('rejects an internally inconsistent %s private scalar even when public coordinates match', async role => {
    configureCertificates();
    const inconsistentJwk = { ...privateJwk, d: otherPrivateJwk.d };
    const inconsistent = createPrivateKey({ key: inconsistentJwk, format: 'jwk' });
    const derived = createPublicKey(inconsistent).export({ format: 'jwk' });
    // Prove that the previous coordinate-only check would accept this imported key.
    expect(derived).toMatchObject({ kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y });
    const challenge = Buffer.from('synthetic malformed-key fixture');
    expect(verify('sha256', challenge, new X509Certificate(readFileSync(certPath)).publicKey,
      sign('sha256', challenge, inconsistent))).toBe(false);
    const suppliedPath = role === 'issuer' ? join(process.env.DATA_DIR!, 'issuer-key.json')
      : join(process.env.DATA_DIR!, 'internally-inconsistent.pem');
    if (role === 'issuer') writeFileSync(suppliedPath,
      JSON.stringify({ kid: 'readiness-fixture', publicKey: publicJwk, privateKey: inconsistentJwk }));
    else {
      writeFileSync(suppliedPath, inconsistent.export({ format: 'pem', type: 'pkcs8' }));
      process.env.EUDI_VERIFIER_KEY_PATH = suppliedPath;
    }
    const before = readFileSync(suppliedPath);
    const filesBefore = readdirSync(process.env.DATA_DIR!);
    const network = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Readiness must remain offline'));
    const body = await getReadiness();
    expect(body.certificates[role].valid).toBe(false);
    expect(body.certificates[role === 'issuer' ? 'verifier' : 'issuer'].valid).toBe(true);
    expect(check(body, role + '_certificate').status).toBe('blocked');
    expect(body.configurationReady).toBe(false);
    expect(body.releaseAccepted).toBe(false);
    expect(readFileSync(suppliedPath)).toEqual(before);
    expect(readdirSync(process.env.DATA_DIR!)).toEqual(filesBefore);
    expect(network).not.toHaveBeenCalled();
    expect(JSON.stringify(body)).not.toContain(otherPrivateJwk.d!);
  });

  it('accepts a locally valid CA chain for both signing roles without inferring external trust', async () => {
    configureCertificates();
    process.env.EUDI_ISSUER_CERT_CHAIN_PATH = chainPaths.valid;
    process.env.EUDI_VERIFIER_CERT_CHAIN_PATH = chainPaths.valid;
    const body = await getReadiness();
    expect(body.certificates.issuer.valid).toBe(true);
    expect(body.certificates.verifier.valid).toBe(true);
    expect(body.releaseAccepted).toBe(false);
    expect(body.checks.filter(item => item.basis === 'independent_acceptance').every(item => item.status === 'not_verified')).toBe(true);
  });

  it.each([
    ['issuer', 'nonCa'], ['issuer', 'unrelated'], ['verifier', 'nonCa'], ['verifier', 'unrelated'],
  ] as const)('blocks %s signing material with a %s parent even when the leaf signature verifies', async (role, kind) => {
    configureCertificates();
    process.env[role === 'issuer' ? 'EUDI_ISSUER_CERT_CHAIN_PATH' : 'EUDI_VERIFIER_CERT_CHAIN_PATH'] = chainPaths[kind];
    const before = readdirSync(process.env.DATA_DIR!);
    const issuerKeyBefore = readFileSync(join(process.env.DATA_DIR!, 'issuer-key.json'));
    const network = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Readiness must remain offline'));
    const body = await getReadiness();
    expect(body.certificates[role].valid).toBe(false);
    expect(body.certificates[role === 'issuer' ? 'verifier' : 'issuer'].valid).toBe(true);
    expect(check(body, role + '_certificate')).toMatchObject({ status: 'blocked', basis: 'local_validation' });
    expect(body.configurationReady).toBe(false);
    expect(body.releaseAccepted).toBe(false);
    expect(body.checks.filter(item => item.basis === 'independent_acceptance').every(item => item.status === 'not_verified')).toBe(true);
    expect(network).not.toHaveBeenCalled();
    expect(readdirSync(process.env.DATA_DIR!)).toEqual(before);
    expect(readFileSync(join(process.env.DATA_DIR!, 'issuer-key.json'))).toEqual(issuerKeyBefore);
    const serialized = JSON.stringify(body);
    for (const value of [chainPaths[kind], keyPath, privateJwk.d!, 'BEGIN CERTIFICATE', 'parent.example.invalid']) expect(serialized).not.toContain(value);
  });

  it('uses supplied configuration without creating a default config or signing key', async () => {
    process.env.DATA_DIR = join(process.env.DATA_DIR!, 'absent-data');
    const body = await getReadiness(structuredClone(DEFAULT_CONFIG));
    expect(body.issuer).toEqual(DEFAULT_CONFIG.issuer);
    expect(existsSync(process.env.DATA_DIR)).toBe(false);
  });

  it('blocks pinned Android readiness when wallet key-attestation policy is missing', async () => {
    configureCertificates();
    const body = await getReadiness();
    expect(check(body, 'android_issuance_contract')).toMatchObject({ status: 'blocked', basis: 'local_validation' });
    expect(body.configurationReady).toBe(false);
    expect(body.releaseAccepted).toBe(false);
  });

  it('accepts locally valid attestation policy while keeping provider and wallet acceptance unverified', async () => {
    configureCertificates();
    vi.mocked(attestation.inspectAttestationPolicy).mockReturnValue({ configured: true, valid: true, providerCount: 2 });
    const body = await getReadiness();
    expect(body.walletAttestation).toEqual({ configured: true, valid: true, providerCount: 2 });
    expect(check(body, 'android_issuance_contract')).toMatchObject({ status: 'ready', basis: 'local_validation' });
    expect(body.configurationReady).toBe(true);
    expect(check(body, 'wallet_attestation_acceptance')).toMatchObject({ status: 'not_verified', basis: 'independent_acceptance' });
    expect(check(body, 'wallet_acceptance').status).toBe('not_verified');
    expect(check(body, 'registration_on_acceptance').status).toBe('not_verified');
    expect(body.releaseAccepted).toBe(false);
  });

  it('blocks configured but invalid wallet-attestation policy', async () => {
    configureCertificates();
    vi.mocked(attestation.inspectAttestationPolicy).mockReturnValue({ configured: true, valid: false, providerCount: 0 });
    const body = await getReadiness();
    expect(check(body, 'android_issuance_contract').status).toBe('blocked');
    expect(body.configurationReady).toBe(false);
    expect(check(body, 'wallet_attestation_acceptance').status).toBe('not_verified');
  });

  it('does not inspect wallet-attestation policy in custom mode', async () => {
    process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH = 'private-attestation-policy-path-sentinel';
    const body = await getReadiness();
    expect(attestation.inspectAttestationPolicy).not.toHaveBeenCalled();
    expect(check(body, 'android_issuance_contract').status).toBe('not_applicable');
    expect(body.walletAttestation).toEqual({ configured: false, valid: false, providerCount: 0 });
    expect(body.configurationReady).toBe(true);
    expect(check(body, 'wallet_attestation_acceptance').status).toBe('not_verified');
    expect(JSON.stringify(body)).not.toContain('private-attestation-policy-path-sentinel');
  });

  it('blocks unexpected attestation inspection failures without exposing paths, keys or errors', async () => {
    configureCertificates();
    process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH = 'private-attestation-policy-path-sentinel';
    vi.mocked(attestation.inspectAttestationPolicy).mockImplementation(() => { throw new Error('private-provider-key-and-error-sentinel'); });
    const body = await getReadiness();
    expect(body.walletAttestation).toEqual({ configured: true, valid: false, providerCount: 0 });
    expect(check(body, 'android_issuance_contract').status).toBe('blocked');
    expect(body.configurationReady).toBe(false);
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain('private-attestation-policy-path-sentinel');
    expect(serialized).not.toContain('private-provider-key-and-error-sentinel');
  });

  it('fails a mismatched verifier key without returning file paths or exception text', async () => {
    configureCertificates();
    const other = await generateKeyPair('ES256', { extractable: true });
    const otherPath = join(process.env.DATA_DIR!, 'private-mismatch.pem');
    writeFileSync(otherPath, await exportPKCS8(other.privateKey));
    process.env.EUDI_VERIFIER_KEY_PATH = otherPath;
    const body = await getReadiness();
    expect(body.certificates.issuer.valid).toBe(true);
    expect(body.certificates.verifier.valid).toBe(false);
    expect(body.configurationReady).toBe(false);
    expect(JSON.stringify(body)).not.toContain('private-mismatch');
  });

  it('does not generate an issuer key when a certificate path is configured but no key exists', async () => {
    configureCertificates(false);
    const before = readdirSync(process.env.DATA_DIR!);
    const body = await getReadiness();
    expect(body.certificates.issuer).toMatchObject({ configured: true, valid: false });
    expect(body.certificates.verifier.valid).toBe(true);
    expect(readdirSync(process.env.DATA_DIR!)).toEqual(before);
  });

  it('blocks expired certificates and incompatible EUDI credential format', async () => {
    configureCertificates();
    vi.spyOn(Date, 'now').mockReturnValue(expiry + 1000);
    const config = loadConfig(); config.credential.format = 'vc+sd-jwt'; saveConfig(config);
    const body = await getReadiness();
    expect(body.certificates.issuer.valid).toBe(false);
    expect(body.certificates.verifier.valid).toBe(false);
    expect(check(body, 'wallet_profile').status).toBe('blocked');
    expect(body.configurationReady).toBe(false);
  });

  it.each(['missing_mapping', 'invalid_options'])('blocks an active credential with %s', async failure => {
    const config = loadConfig();
    if (failure === 'missing_mapping') config.fieldMappings = {};
    else config.templateOptions = { ageThresholds: [18, 18] };
    saveConfig(config);
    const body = await getReadiness();
    expect(body.credentials.find(item => item.active)?.configured).toBe(false);
    expect(check(body, 'credential_configuration').status).toBe('blocked');
    expect(body.configurationReady).toBe(false);
  });


  it('requires separate issuer and verifier registration material when policy is required', async () => {
    configureCertificates();
    process.env.EUDI_REGISTRATION_POLICY = 'required';
    const before = readdirSync(process.env.DATA_DIR!);
    const body = await getReadiness();
    expect(body.registrations).toEqual({ required: true, policyValid: true,
      issuer: { configured: false, valid: null, expiresAt: null }, verifier: { configured: false, valid: null, expiresAt: null } });
    expect(check(body, 'issuer_registrar_dataset').status).toBe('blocked');
    expect(check(body, 'issuer_registration_transport').status).toBe('blocked');
    expect(check(body, 'verifier_registration_transport').status).toBe('blocked');
    expect(check(body, 'registration_on_acceptance')).toMatchObject({ status: 'not_verified', basis: 'independent_acceptance' });
    expect(body.configurationReady).toBe(false);
    expect(body.releaseAccepted).toBe(false);
    expect(readdirSync(process.env.DATA_DIR!)).toEqual(before);
  });

  it('does not treat optional missing registration as either local validation or independent acceptance', async () => {
    configureCertificates();
    vi.mocked(attestation.inspectAttestationPolicy).mockReturnValue({ configured: true, valid: true, providerCount: 1 });
    const body = await getReadiness();
    expect(body.registrations.required).toBe(false);
    expect(check(body, 'issuer_registration_transport').status).toBe('not_verified');
    expect(check(body, 'verifier_registration_transport').status).toBe('not_verified');
    expect(check(body, 'registration_on_acceptance').status).toBe('not_verified');
    expect(body.configurationReady).toBe(true);
    expect(body.releaseAccepted).toBe(false);
  });

  it('does not inspect registration material in custom mode', async () => {
    const inspection = vi.spyOn(registration, 'inspectRegistration');
    const body = await getReadiness();
    expect(inspection).not.toHaveBeenCalled();
    expect(check(body, 'issuer_registration_transport').status).toBe('not_applicable');
    expect(check(body, 'verifier_registration_transport').status).toBe('not_applicable');
    expect(check(body, 'registration_on_acceptance').status).toBe('not_verified');
  });

  it('blocks invalid registration policy without exposing its value', async () => {
    configureCertificates();
    process.env.EUDI_REGISTRATION_POLICY = 'private-registration-policy-sentinel';
    const body = await getReadiness();
    expect(body.registrations.policyValid).toBe(false);
    expect(check(body, 'registration_policy')).toMatchObject({ status: 'blocked', basis: 'configuration' });
    expect(body.configurationReady).toBe(false);
    expect(JSON.stringify(body)).not.toContain('private-registration-policy-sentinel');
  });

  it('keeps registration trust and enabled-wallet acceptance unverified after local registration validation', async () => {
    configureCertificates();
    vi.mocked(attestation.inspectAttestationPolicy).mockReturnValue({ configured: true, valid: true, providerCount: 1 });
    process.env.EUDI_REGISTRATION_POLICY = 'required';
    vi.spyOn(registration, 'inspectRegistration').mockResolvedValue({ configured: true, valid: true, expiresAt: new Date(expiry).toISOString() });
    vi.spyOn(registration, 'inspectRegistrarDataset').mockReturnValue({ configured: true, valid: true });
    const body = await getReadiness();
    expect(check(body, 'issuer_registration_transport')).toMatchObject({ status: 'ready', basis: 'local_validation' });
    expect(check(body, 'verifier_registration_transport')).toMatchObject({ status: 'ready', basis: 'local_validation' });
    expect(check(body, 'registration_on_acceptance').status).toBe('not_verified');
    expect(body.configurationReady).toBe(true);
    expect(body.releaseAccepted).toBe(false);
  });

  it('blocks configured invalid registration even when the registration policy is optional', async () => {
    configureCertificates();
    vi.spyOn(registration, 'inspectRegistrarDataset').mockReturnValue({ configured: true, valid: false });
    vi.spyOn(registration, 'inspectRegistration').mockImplementation(async role => ({ configured: role === 'issuer', valid: role === 'issuer' ? false : null, expiresAt: null }));
    const body = await getReadiness();
    expect(check(body, 'issuer_registration_transport').status).toBe('blocked');
    expect(check(body, 'verifier_registration_transport').status).toBe('not_verified');
    expect(body.configurationReady).toBe(false);
  });

  it('returns a generic blocked check when local registration inspection fails', async () => {
    configureCertificates();
    vi.spyOn(registration, 'inspectRegistration').mockRejectedValue(new Error('private-registration-path-and-jwt-sentinel'));
    const body = await getReadiness();
    expect(check(body, 'issuer_registration_transport').status).toBe('blocked');
    expect(check(body, 'verifier_registration_transport').status).toBe('blocked');
    expect(body.configurationReady).toBe(false);
    expect(JSON.stringify(body)).not.toContain('private-registration-path-and-jwt-sentinel');
  });

  it('returns a generic non-cacheable failure if current configuration cannot be inspected', async () => {
    writeFileSync(configPath(), '{ invalid-private-config-sentinel');
    const response = await request();
    expect(response.status).toBe(503);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json();
    expect(body).toEqual({ error: 'readiness_unavailable', detail: 'Readiness could not be determined from the current configuration.' });
    expect(JSON.stringify(body)).not.toContain('invalid-private-config-sentinel');
  });
});
