import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { exportPKCS8, generateKeyPair, SignJWT, type KeyLike } from 'jose';
import { getIssuerKeyPair } from '../../keys/manager.js';
import { certificateSigner } from '../profile.js';
import { registrationCertificate } from '../registration.js';

let dir: string, privateKey: KeyLike, chainPath: string;
let leaf: X509Certificate, parent: X509Certificate, nonCa: X509Certificate, unrelated: X509Certificate;
function openssl(args: string[]) {
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  execFileSync(process.env.OPENSSL_BIN ?? (existsSync(bundled) ? bundled : 'openssl'), args, { stdio: 'pipe', windowsHide: true });
}
beforeAll(async () => {
  dir = mkdtempSync(join(process.env.DATA_DIR!, 'chain-validation-'));
  chainPath = join(dir, 'chain.pem');
  privateKey = (await getIssuerKeyPair()).privateKey;
  const keyPath = join(dir, 'leaf-key.pem');
  const parentKey = join(dir, 'parent-key.pem');
  writeFileSync(keyPath, await exportPKCS8(privateKey));
  writeFileSync(parentKey, await exportPKCS8((await generateKeyPair('ES256', { extractable: true })).privateKey));
  function parentCertificate(name: string, subject: string, ca: boolean) {
    const path = join(dir, name + '.crt');
    openssl(['req', '-new', '-x509', '-key', parentKey, '-out', path, '-days', '2', '-subj', '/CN=' + subject,
      '-addext', 'basicConstraints=critical,CA:' + (ca ? 'TRUE' : 'FALSE'),
      '-addext', 'keyUsage=critical,digitalSignature,keyCertSign']);
    return new X509Certificate(readFileSync(path));
  }
  parent = parentCertificate('parent', 'synthetic-parent', true);
  // Same public key: a signature-only check cannot distinguish these invalid replacements.
  nonCa = parentCertificate('nonca', 'synthetic-parent', false);
  unrelated = parentCertificate('unrelated', 'unrelated-issuer', true);
  const csr = join(dir, 'leaf.csr'); const certificate = join(dir, 'leaf.crt');
  const extensions = join(dir, 'leaf.ext');
  writeFileSync(extensions, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
  openssl(['req', '-new', '-key', keyPath, '-out', csr, '-subj', '/CN=synthetic-leaf']);
  openssl(['x509', '-req', '-in', csr, '-CA', join(dir, 'parent.crt'), '-CAkey', parentKey,
    '-set_serial', '1', '-out', certificate, '-days', '2', '-extfile', extensions]);
  leaf = new X509Certificate(readFileSync(certificate));
});
beforeEach(() => {
  process.env.EUDI_ISSUER_CERT_CHAIN_PATH = chainPath;
  process.env.EUDI_VERIFIER_CERT_CHAIN_PATH = chainPath;
  process.env.EUDI_VERIFIER_KEY_PATH = join(dir, 'leaf-key.pem');
  process.env.EUDI_ISSUER_REGISTRATION_CERT_PATH = join(dir, 'registration.jwt');
});
function chain(certificates: X509Certificate[]) { writeFileSync(chainPath, certificates.map(cert => cert.toString()).join('\n')); }
async function registration(certificates: X509Certificate[]) {
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ sub: 'synthetic-organization', iat: now, exp: now + 300,
    status: { status_list: { idx: 0, uri: 'https://registrar.example.invalid/status/1' } } })
    .setProtectedHeader({ alg: 'ES256', typ: 'rc-wrp+jwt', x5c: certificates.map(cert => cert.raw.toString('base64')) })
    .sign(privateKey);
  writeFileSync(process.env.EUDI_ISSUER_REGISTRATION_CERT_PATH!, token);
}

describe('local signing-chain consistency (not ecosystem trust)', () => {
  it.each(['issuer', 'verifier'] as const)('accepts a consistent %s chain and matching key', async role => {
    chain([leaf, parent]);
    expect((await certificateSigner(role)).x5c).toHaveLength(2);
  });
  it.each(['issuer', 'verifier'] as const)('rejects a non-CA parent for %s even when its key verifies the signature', async role => {
    expect(leaf.verify(nonCa.publicKey)).toBe(true);
    chain([leaf, nonCa]);
    await expect(certificateSigner(role)).rejects.toThrow('Certificate chain issuer or signature mismatch');
  });
  it.each(['issuer', 'verifier'] as const)('rejects an unrelated parent identity for %s even with the same signing key', async role => {
    expect(leaf.verify(unrelated.publicKey)).toBe(true);
    chain([leaf, unrelated]);
    await expect(certificateSigner(role)).rejects.toThrow('Certificate chain issuer or signature mismatch');
  });
  it('accepts an internally consistent registration chain without claiming external trust', async () => {
    await registration([leaf, parent]);
    expect(await registrationCertificate('issuer')).toBeDefined();
  });
  it('rejects a registration chain with a non-CA parent', async () => {
    await registration([leaf, nonCa]);
    await expect(registrationCertificate('issuer')).rejects.toThrow('failed local validation');
  });
  it('rejects a registration chain with an unrelated parent identity', async () => {
    await registration([leaf, unrelated]);
    await expect(registrationCertificate('issuer')).rejects.toThrow('failed local validation');
  });
});
