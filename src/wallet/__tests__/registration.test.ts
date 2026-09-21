import { beforeAll, beforeEach, afterEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { SignJWT, exportPKCS8, generateKeyPair, type KeyLike, type JWTPayload } from 'jose';
import { inspectRegistration, registrationCertificate, registrationInfo, registrationRequired } from '../registration.js';

let privateKey: KeyLike;
let certificate: X509Certificate;
let path: string;
const envNames = ['EUDI_REGISTRATION_POLICY', 'EUDI_ISSUER_REGISTRATION_CERT_PATH', 'EUDI_VERIFIER_REGISTRATION_CERT_PATH'] as const;
const initial = Object.fromEntries(envNames.map(name => [name, process.env[name]]));
async function token(overrides: JWTPayload = {}, header: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: 'SYNTHETIC-UNREGISTERED-ORGANIZATION', iat: now, exp: now + 300,
    status: { status_list: { idx: 0, uri: 'https://registrar.example.invalid/status/1' } }, ...overrides })
    .setProtectedHeader({ alg: 'ES256', typ: 'rc-wrp+jwt', x5c: [certificate.raw.toString('base64')], ...header })
    .sign(privateKey);
}
beforeAll(async () => {
  const dir = mkdtempSync(join(process.env.DATA_DIR!, 'registration-'));
  const keyPath = join(dir, 'synthetic-provider.pem');
  const certPath = join(dir, 'synthetic-provider.crt');
  path = join(dir, 'registration.jwt');
  privateKey = (await generateKeyPair('ES256', { extractable: true })).privateKey;
  writeFileSync(keyPath, await exportPKCS8(privateKey));
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  execFileSync(process.env.OPENSSL_BIN ?? (existsSync(bundled) ? bundled : 'openssl'),
    ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '2', '-subj', '/CN=synthetic-untrusted-registrar',
      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature'], { stdio: 'pipe', windowsHide: true });
  certificate = new X509Certificate(readFileSync(certPath));
});
beforeEach(() => { for (const name of envNames) delete process.env[name]; });
afterEach(() => { for (const name of envNames) { if (initial[name] === undefined) delete process.env[name]; else process.env[name] = initial[name]; } });
function provision(compact: string) {
  writeFileSync(path, compact);
  process.env.EUDI_ISSUER_REGISTRATION_CERT_PATH = path;
}

describe('Registration JWT transport integrity (no external trust or wallet acceptance)', () => {
  it('omits absent optional material and fails closed when required', async () => {
    expect(registrationRequired()).toBe(false);
    expect(await registrationInfo('issuer')).toBeUndefined();
    expect(await inspectRegistration('issuer')).toEqual({ configured: false, valid: null, expiresAt: null });
    process.env.EUDI_REGISTRATION_POLICY = 'required';
    await expect(registrationCertificate('issuer')).rejects.toThrow('not configured');
    await expect(registrationCertificate('verifier')).rejects.toThrow('not configured');
  });
  it('rejects unknown policy without printing the supplied value', async () => {
    process.env.EUDI_REGISTRATION_POLICY = 'private-policy-sentinel';
    await expect(registrationInfo('issuer')).rejects.toThrow('Unsupported EUDI registration policy');
  });
  it('passes an unchanged compact JWT encoded as ETSI base64url data, without credential_ids', async () => {
    const compact = await token(); provision(compact);
    const info = await registrationInfo('issuer');
    expect(info).toEqual([{ format: 'registration_cert', data: Buffer.from(compact).toString('base64url') }]);
    expect(Buffer.from(info![0].data as string, 'base64url').toString()).toBe(compact);
    const inspected = await inspectRegistration('issuer');
    expect(inspected.valid).toBe(true); // Cryptographic integrity only: this signer has no external trust.
    expect(JSON.stringify(inspected)).not.toContain(compact);
    expect(JSON.stringify(inspected)).not.toContain(path);
    expect(JSON.stringify(inspected)).not.toContain('SYNTHETIC-UNREGISTERED');
  });
  it('keeps role material separate', async () => {
    provision(await token());
    expect(await registrationInfo('verifier')).toBeUndefined();
    process.env.EUDI_REGISTRATION_POLICY = 'required';
    await expect(registrationInfo('verifier')).rejects.toThrow('not configured');
  });
  it('rejects an altered payload with the original signature even when material is optional', async () => {
    const parts = (await token()).split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    payload.sub = 'altered-subject'; parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
    provision(parts.join('.'));
    await expect(registrationInfo('issuer')).rejects.toThrow('failed local validation');
    expect(await inspectRegistration('issuer')).toEqual({ configured: true, valid: false, expiresAt: null });
  });
  it.each([
    ['expired', { exp: 1 }],
    ['future issuance', { iat: Math.floor(Date.now() / 1000) + 120 }],
    ['missing identity', { sub: '' }],
    ['missing status', { status: undefined }],
    ['negative index', { status: { status_list: { idx: -1, uri: 'https://example.invalid/status' } } }],
    ['index outside pinned wallet range', { status: { status_list: { idx: 2147483648, uri: 'https://example.invalid/status' } } }],
    ['fractional index', { status: { status_list: { idx: 0.5, uri: 'https://example.invalid/status' } } }],
    ['insecure status', { status: { status_list: { idx: 0, uri: 'http://example.invalid/status' } } }],
    ['status userinfo', { status: { status_list: { idx: 0, uri: 'https://private:secret@example.invalid/status' } } }],
  ])('rejects %s without a network lookup or token disclosure', async (_name, payload) => {
    provision(await token(payload as JWTPayload));
    await expect(registrationInfo('issuer')).rejects.toThrow('failed local validation');
  });
  it.each([
    ['wrong type', { typ: 'JWT' }], ['missing chain', { x5c: undefined }], ['invalid chain', { x5c: ['invalid'] }],
  ])('rejects %s', async (_name, header) => {
    provision(await token({}, header));
    await expect(registrationInfo('issuer')).rejects.toThrow('failed local validation');
  });
  it.each(['malformed.jwt.value', 'x'.repeat(128 * 1024 + 1)])('rejects malformed or oversized files', async compact => {
    provision(compact);
    await expect(registrationInfo('issuer')).rejects.toThrow('failed local validation');
  });
});
