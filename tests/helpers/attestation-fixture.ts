import { generateKeyPair, exportPKCS8, exportJWK, SignJWT, type JWK, type JWTPayload } from 'jose';
import { writeFileSync, readFileSync, existsSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { X509Certificate, createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { deflateSync } from 'node:zlib';

/** Synthetic local material only. Never install these pins in a live acceptance environment. */
export async function attestationFixture() {
  const dir = mkdtempSync(join(process.env.DATA_DIR!, 'wallet-attestation-'));
  async function signer(name: string) {
    const pair = await generateKeyPair('ES256', { extractable: true });
    const keyPath = join(dir, name + '.pem'); const certPath = join(dir, name + '.crt');
    writeFileSync(keyPath, await exportPKCS8(pair.privateKey));
    const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
    execFileSync(process.env.OPENSSL_BIN ?? (existsSync(bundled) ? bundled : 'openssl'),
      ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '2', '-subj', '/CN=' + name + '.example.invalid',
        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature'], { stdio: 'pipe', windowsHide: true });
    const certificate = new X509Certificate(readFileSync(certPath));
    return { ...pair, certificate, pin: createHash('sha256').update(certificate.raw).digest('hex') };
  }
  const provider = await signer('synthetic-wallet-provider'); const status = await signer('synthetic-status-provider');
  const statusUri = 'https://wallet-status.example.invalid/lists/one';
  const certification = 'https://wallet-provider.example.invalid/certification/synthetic';
  const policy = { version: 1, maxAttestationAgeSeconds: 300, maxStatusAgeSeconds: 120, providers: [{ id: 'synthetic-wallet-provider',
    signingCertificateSha256: [provider.pin], statusSigningCertificateSha256: [status.pin],
    statusListPrefixes: ['https://wallet-status.example.invalid/lists/'], keyStorage: ['iso_18045_high'],
    userAuthentication: ['iso_18045_high'], certifications: [certification] }] };
  const policyPath = join(dir, 'policy.json');
  const provision = () => { writeFileSync(policyPath, JSON.stringify(policy)); process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH = policyPath; };
  provision();
  async function attestation(keys: JWK[], nonce: string | undefined, overrides: JWTPayload = {}, header: Record<string, unknown> = {}, signing = provider) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ iat: now, exp: now + 300, attested_keys: keys, nonce,
      key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'], certification,
      key_storage_status: { status: { status_list: { idx: 0, uri: statusUri } }, exp: now + 400 * 86400 }, ...overrides })
      .setProtectedHeader({ alg: 'ES256', typ: 'key-attestation+jwt', x5c: [signing.certificate.raw.toString('base64')], ...header }).sign(signing.privateKey);
  }
  async function statusToken(overrides: JWTPayload = {}, bitmap: Uint8Array = Buffer.from([0]), bits = 1, signing = status) {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ sub: statusUri, iat: now, exp: now + 120, ttl: 60,
      status_list: { bits, lst: deflateSync(bitmap).toString('base64url') }, ...overrides })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt', x5c: [signing.certificate.raw.toString('base64')] }).sign(signing.privateKey);
  }
  return { dir, provider, status, policy, policyPath, provision, statusUri, certification, attestation, statusToken, exportJWK };
}
