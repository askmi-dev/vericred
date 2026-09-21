import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync } from 'node:fs';
import { chmod, lstat, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes, randomUUID, X509Certificate } from 'node:crypto';
import { exportJWK, exportPKCS8, generateKeyPair, SignJWT } from 'jose';

const exec = promisify(execFile);
const artifacts = resolve(dirname(fileURLToPath(import.meta.url)), '../../.validation-artifacts');

/** Disposable synthetic local proxy material; no external EUDI trust or wallet acceptance. */
export async function createSyntheticEudiMaterial(root, origin) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' || !['localhost', '127.0.0.1'].includes(url.hostname) ||
      url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Synthetic EUDI material requires a loopback HTTPS origin');
  }
  const target = resolve(root);
  const stat = await lstat(target);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('Synthetic fixture root must be an existing directory');
  const relativeRoot = relative(await realpath(artifacts), await realpath(target));
  if (!relativeRoot || relativeRoot === '..' || relativeRoot.startsWith('..\\') ||
      relativeRoot.startsWith('../') || isAbsolute(relativeRoot)) {
    throw new Error('Synthetic fixture root must be inside this checkout validation artifacts');
  }
  if ((await readdir(target)).length) throw new Error('Synthetic fixture root must be empty');
  const data = join(target, 'data'), material = join(target, 'material');
  await mkdir(data, { mode: 0o700 });
  await mkdir(material, { mode: 0o700 });
  async function write(path, value) {
    await writeFile(path, value, { flag: 'wx', mode: 0o600 });
  }
  const bundledOpenSSL = 'C:/Program Files/Git/usr/bin/openssl.exe';
  const openssl = process.env.OPENSSL_BIN ?? (existsSync(bundledOpenSSL) ? bundledOpenSSL : 'openssl');
  async function signer(name, certName = name + '-cert.pem', keyName = name + '-key.pem') {
    const pair = await generateKeyPair('ES256', { extractable: true });
    const keyPath = join(material, keyName), certPath = join(material, certName);
    await write(keyPath, await exportPKCS8(pair.privateKey));
    try {
      await exec(openssl, ['req', '-new', '-x509', '-key', keyPath, '-out', certPath,
        '-days', '2', '-subj', '/CN=synthetic-' + name + '.example.invalid',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
        '-addext', 'basicConstraints=critical,CA:FALSE',
        '-addext', 'keyUsage=critical,digitalSignature',
        ...(name === 'tls' ? ['-addext', 'extendedKeyUsage=serverAuth'] : [])],
      { windowsHide: true, timeout: 15000, maxBuffer: 64 * 1024 });
    } catch { throw new Error('OpenSSL failed to generate synthetic local certificates'); }
    await chmod(certPath, 0o600);
    const certificate = new X509Certificate(await readFile(certPath));
    return { ...pair, certificate, pin: createHash('sha256').update(certificate.raw).digest('hex') };
  }
  const issuer = await signer('issuer', 'issuer-chain.pem');
  await signer('verifier', 'verifier-chain.pem');
  await signer('tls');
  const registrar = await signer('registrar');
  const provider = await signer('wallet-provider');
  const status = await signer('wallet-status-provider');
  await write(join(data, 'issuer-key.json'), JSON.stringify({
    publicKey: await exportJWK(issuer.publicKey), privateKey: await exportJWK(issuer.privateKey), kid: randomUUID(),
  }, null, 2));
  await write(join(data, 'key-history.json'), '[]');
  await write(join(data, 'holders.json'), JSON.stringify([{
    id: 'synthetic-adult', firstName: 'Alex', lastName: 'Example', email: 'alex@example.invalid',
    dateOfBirth: '1990-01-01', organization: 'VeriCred Synthetic Example', role: 'Engineer',
  }], null, 2));
  await write(join(data, 'vericred.config.json'), JSON.stringify({
    revision: 1,
    issuer: { name: 'VeriCred Synthetic Caddy Acceptance', url: url.origin, did: 'did:web:' + url.host.replaceAll(':', '%3A') },
    credential: { type: 'AgeCredential', format: 'dc+sd-jwt', expiresInDays: 30 },
    dataSource: { type: 'json', path: '/app/data/holders.json' },
    fieldMappings: { dateOfBirth: 'dateOfBirth' },
    templateOptions: { ageThresholds: [18, 21], jurisdiction: 'AT' },
  }, null, 2));
  for (const role of ['issuer', 'verifier']) {
    const common = { identifier: [{ type: 'https://registrar.example.invalid/identifier-type', identifier: 'SYNTHETIC-' + role }],
      srvDescription: [{ lang: 'en', content: 'Synthetic ' + role + ' service' }], registryURI: 'https://registrar.example.invalid/api' };
    const dataset = role === 'issuer' ? { ...common, providesAttestations: [{ format: 'dc+sd-jwt', type: 'urn:vericred:credential:AgeCredential:1' }] }
      : { ...common, intendedUseIdentifier: 'synthetic-age-check', purpose: [{ lang: 'en', content: 'Synthetic age check' }], policyURI: 'https://registrar.example.invalid/privacy' };
    await write(join(material, role + '-registrar-dataset.json'), JSON.stringify(dataset));
  }
  const now = Math.floor(Date.now() / 1000);
  for (const role of ['issuer', 'verifier']) {
    const registration = await new SignJWT({
      sub: 'synthetic-' + role + '.example.invalid', iat: now, exp: now + 86400,
      status: { status_list: { idx: 0, uri: 'https://registration-status.example.invalid/lists/synthetic' } },
    }).setProtectedHeader({ alg: 'ES256', typ: 'rc-wrp+jwt', x5c: [registrar.certificate.raw.toString('base64')] })
      .sign(registrar.privateKey);
    await write(join(material, role + '-registration.jwt'), registration);
  }
  await write(join(material, 'wallet-attestation-policy.json'), JSON.stringify({
    version: 1, maxAttestationAgeSeconds: 300, maxStatusAgeSeconds: 120,
    providers: [{
      id: 'synthetic-wallet-provider', signingCertificateSha256: [provider.pin],
      statusSigningCertificateSha256: [status.pin],
      statusListPrefixes: ['https://wallet-status.example.invalid/lists/'],
      keyStorage: ['iso_18045_high'], userAuthentication: ['iso_18045_high'],
      certifications: ['https://wallet-provider.example.invalid/certification/synthetic'],
    }],
  }, null, 2));
  return { issuerFingerprint: issuer.pin, adminApiKey: randomBytes(32).toString('hex'), pseudonymSecret: randomBytes(32).toString('hex') };
}
