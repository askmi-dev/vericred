import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, verify, X509Certificate } from 'crypto';
import { spawnSync } from 'child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { buildCsr } from '../csr.js';
import { validateCertificateChain } from '../x5c.js';

const ISSUER_URL = 'https://issuer.example.test';
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const csrFor = () => buildCsr({
  privateKey, publicKey,
  subject: { commonName: 'issuer.example.test', organization: 'Müller & Co', country: 'DE' },
  sanUris: [ISSUER_URL],
  sanDns: ['issuer.example.test'],
});

// Minimal DER reader: [tag, header length, content length] at offset.
function readTlv(buf: Buffer, at: number) {
  let len = buf[at + 1]!;
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[at + 2 + i]!;
    hdr += n;
  }
  return { tag: buf[at]!, hdr, len, end: at + hdr + len };
}

const hasOpenssl = spawnSync('openssl', ['version']).status === 0;
const env = { ...process.env, MSYS_NO_PATHCONV: '1' };
const ossl = (cwd: string, ...args: string[]) => {
  const r = spawnSync('openssl', args, { cwd, env, encoding: 'utf-8' });
  if (r.status !== 0) throw new Error(`openssl ${args[0]} failed: ${r.stderr}`);
  return r.stdout;
};

describe('issuer CSR', () => {
  it('is a PKCS#10 request signed by the issuer key', () => {
    const pem = csrFor();
    expect(pem).toMatch(/^-----BEGIN CERTIFICATE REQUEST-----\n/);
    const der = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ''), 'base64');

    const outer = readTlv(der, 0);
    expect(outer.tag).toBe(0x30);
    expect(outer.end).toBe(der.length);
    const info = readTlv(der, outer.hdr);
    const algo = readTlv(der, info.end);
    const sig = readTlv(der, algo.end);
    expect(sig.tag).toBe(0x03);

    const signed = der.subarray(outer.hdr, info.end);
    const signature = der.subarray(algo.end + sig.hdr + 1, sig.end); // skip unused-bits byte
    expect(verify('sha256', signed, publicKey, signature)).toBe(true);
  });

  it('rejects input a CA would refuse', () => {
    const base = { privateKey, publicKey, subject: { commonName: 'x' } };
    expect(() => buildCsr({ ...base, subject: { commonName: ' ' } })).toThrow(/commonName/);
    expect(() => buildCsr({ ...base, subject: { commonName: 'x', country: 'Germany' } })).toThrow(/country/);
    expect(() => buildCsr({ ...base, sanDns: ['müller.example'] })).toThrow(/ASCII/);
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
    expect(() => buildCsr({ ...rsa, subject: { commonName: 'x' } })).toThrow(/P-256/);
  });

  it.skipIf(!hasOpenssl)('passes openssl verification with the requested subject and SAN', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vericred-csr-'));
    try {
      writeFileSync(join(dir, 'issuer.csr'), csrFor());
      const text = ossl(dir, 'req', '-in', 'issuer.csr', '-verify', '-noout', '-text', '-nameopt', 'utf8');
      expect(text).toContain('C=DE, O=Müller & Co, CN=issuer.example.test');
      expect(text).toContain('URI:https://issuer.example.test, DNS:issuer.example.test');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it.skipIf(!hasOpenssl)('yields a certificate that x5c validation accepts once a CA signs it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vericred-csr-'));
    try {
      const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
      writeFileSync(join(dir, 'ca.ext'), 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n');
      writeFileSync(join(dir, 'leaf.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
      ossl(dir, 'req', '-x509', ...ec, '-keyout', 'root.key', '-out', 'root.pem', '-days', '2', '-subj', '/CN=Test Root',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
      ossl(dir, 'req', ...ec, '-keyout', 'int.key', '-out', 'int.csr', '-subj', '/CN=Test Registrar CA');
      ossl(dir, 'x509', '-req', '-in', 'int.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial',
        '-out', 'int.pem', '-days', '2', '-extfile', 'ca.ext');
      // The registrar's step: sign OUR CSR, keeping the SAN we asked for.
      writeFileSync(join(dir, 'issuer.csr'), csrFor());
      ossl(dir, 'x509', '-req', '-in', 'issuer.csr', '-CA', 'int.pem', '-CAkey', 'int.key', '-CAcreateserial',
        '-out', 'leaf.pem', '-days', '1', '-extfile', 'leaf.ext', '-copy_extensions', 'copy');

      const chain = ['leaf.pem', 'int.pem'].map(f => new X509Certificate(readFileSync(join(dir, f))));
      expect(validateCertificateChain(chain, publicKey, ISSUER_URL)).toHaveLength(2);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
});
