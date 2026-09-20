import { attestationFixture } from './helpers/attestation-fixture.js';
import { beforeAll, afterAll, afterEach, it, expect } from 'vitest';
import express from 'express';
import { createServer, type Server } from 'node:https';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash, X509Certificate } from 'node:crypto';
import { exportPKCS8, decodeJwt, decodeProtectedHeader, SignJWT } from 'jose';
import { getIssuerKeyPair } from '../src/keys/manager.js';
import { loadConfig, saveConfig } from '../src/config/loader.js';
import { createMetadataRouter } from '../src/oid4vci/metadata.js';
import { createTokenRouter } from '../src/oid4vci/token.js';
import { createCredentialRouter } from '../src/oid4vci/issuer.js';
import { securityHeaders } from '../src/middleware/security.js';

const exec = promisify(execFile);
let server: Server;
let fault: string | undefined;
afterEach(() => { fault = undefined; });
let origin: string, certPath: string, fingerprint: string;
beforeAll(async () => {
  const dir = process.env.DATA_DIR!;
  const keys = await getIssuerKeyPair();
  const keyPath = join(dir, 'https-test.pem');
  certPath = join(dir, 'https-test.crt');
  writeFileSync(keyPath, await exportPKCS8(keys.privateKey), { mode: 0o600 });
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  execFileSync(process.env.OPENSSL_BIN ?? (existsSync(bundled) ? bundled : 'openssl'),
    ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '2', '-subj', '/CN=localhost',
      '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
      '-addext', 'keyUsage=critical,digitalSignature'], { stdio: 'pipe', windowsHide: true });
  await attestationFixture(); // Metadata policy only; this test makes no wallet-provider request.
  process.env.WALLET_PROFILE = 'eudi-android';
  process.env.EUDI_ISSUER_CERT_CHAIN_PATH = certPath;
  const certificate = new X509Certificate(readFileSync(certPath));
  fingerprint = createHash('sha256').update(certificate.raw).digest('hex');
  const app = express();
  app.use(securityHeaders('stitch-out/dist'), express.json());
  app.use((req, res, next) => {
    if (req.path !== '/.well-known/openid-credential-issuer') return next();
    const send = res.send.bind(res);
    res.send = ((value: unknown) => {
      if (fault === 'oversize' && req.get('Accept') === 'application/jwt') return send('x'.repeat(1024 * 1024 + 1));
      if (fault?.startsWith('unsigned-') && req.get('Accept') === 'application/json' && typeof value === 'string') {
        const payload = JSON.parse(value);
        if (fault === 'unsigned-endpoint') payload.credential_endpoint += '/changed';
        if (fault === 'unsigned-registration') payload.issuer_info = [{ format: 'registration_cert', data: 'changed' }];
        return send(JSON.stringify(payload));
      }
      if (fault?.startsWith('signed-') && req.get('Accept') === 'application/jwt' && typeof value === 'string') {
        const payload = decodeJwt(value);
        if (fault === 'signed-empty') payload.credential_configurations_supported = {};
        if (fault === 'signed-attestation') {
          for (const config of Object.values(payload.credential_configurations_supported as Record<string, any>)) {
            delete config.proof_types_supported.jwt.key_attestations_required;
          }
        }
        if (fault === 'signed-future') payload.iat = Math.floor(Date.now() / 1000) + 120;
        void new SignJWT(payload).setProtectedHeader(decodeProtectedHeader(value)).sign(keys.privateKey)
          .then(token => send(token)).catch(() => res.status(500).end());
        return res;
      }
      return send(value);
    }) as typeof res.send;
    next();
  });
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.use(createMetadataRouter(), createTokenRouter(), createCredentialRouter(process.env.PSEUDO_SECRET!));
  server = createServer({ key: readFileSync(keyPath), cert: readFileSync(certPath) }, app);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = 'https://127.0.0.1:' + (server.address() as { port: number }).port;
  const config = loadConfig();
  config.issuer = { name: 'Local TLS fixture', url: origin, did: 'did:web:127.0.0.1' };
  saveConfig(config);
});
afterAll(async () => { if (server) await new Promise<void>(resolve => server.close(() => resolve())); });
function run(pin: string) {
  return exec(process.execPath, ['scripts/https-preflight.mjs', origin], {
    env: { ...process.env, NODE_EXTRA_CA_CERTS: certPath, EUDI_ISSUER_CERT_SHA256: pin, NODE_TLS_REJECT_UNAUTHORIZED: '1' },
    windowsHide: true, timeout: 20000,
  });
}
it('executes HTTPS preflight with actual TLS validation and pinned signed metadata (local fixture)', async () => {
  const result = await run(fingerprint);
  expect(JSON.parse(result.stdout)).toMatchObject({ status: 'PASS', independentWalletAcceptance: 'NOT RUN', origin });
});
it('rejects an unexpected signer even when TLS is trusted', async () => {
  await expect(run('00'.repeat(32))).rejects.toMatchObject({ code: 1, stderr: expect.stringContaining('does not match') });
});


it.each([
  ['unsigned-endpoint', 'Signed and unsigned metadata disagree'],
  ['unsigned-registration', 'Signed and unsigned metadata disagree'],
  ['signed-empty', 'No credential configurations advertised'],
  ['signed-attestation', 'Missing key attestation requirements'],
  ['signed-future', 'Metadata freshness'],
  ['oversize', 'Response exceeds preflight size limit'],
])('rejects %s through actual local TLS', async (mode, message) => {
  fault = mode;
  await expect(run(fingerprint)).rejects.toMatchObject({ code: 1, stderr: expect.stringContaining(message) });
});

it('redacts changed registration payloads from mismatch diagnostics', async () => {
  fault = 'unsigned-registration';
  await expect(run(fingerprint)).rejects.toMatchObject({ code: 1,
    stderr: 'HTTPS preflight failed: Signed and unsigned metadata disagree\n' });
});
