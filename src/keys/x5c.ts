/**
 * x5c — the issuer's X.509 certificate chain in the JWS header (RFC 7515
 * §4.1.6), as HAIP 1.0 requires on SD-JWT VCs and Status List Tokens. EUDI
 * wallets trust issuers through certificates from a registrar, not DIDs.
 *
 * Optional: without `issuer.certificateChain` everything is signed as before
 * (`iss` = did:web, no x5c). With it, `iss` becomes `issuer.url`, because a
 * verifier must match `iss` against the leaf certificate's SAN.
 *
 * Fail-closed: a chain that wallets would reject (wrong key, expired, wrong
 * order, self-signed, SAN mismatch) stops issuance instead of producing
 * credentials that silently fail verification.
 */
import { readFileSync } from 'fs';
import { X509Certificate, KeyObject, createPublicKey } from 'crypto';
import type { JsonWebKey } from 'crypto';
import type { KeyLike } from 'jose';
import type { VeriCredConfig } from '../config/types.js';
import { getKeyProvider } from './provider.js';

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;

export function parseCertificateChain(pem: string): X509Certificate[] {
  const blocks = pem.match(PEM_CERT) ?? [];
  if (blocks.length === 0) throw new Error('[x5c] no PEM certificate found in certificate chain file');
  return blocks.map(b => new X509Certificate(b));
}

const isSelfSigned = (c: X509Certificate) => c.checkIssued(c) && c.verify(c.publicKey);
const stripSlash = (u: string) => u.replace(/\/+$/, '');

/**
 * Checks the chain against the issuer key and URL. Returns the x5c header
 * value: standard Base64 DER (not base64url), leaf first, trust anchor excluded.
 */
export function validateCertificateChain(
  certs: X509Certificate[],
  issuerPublicKey: KeyLike | KeyObject,
  issuerUrl: string,
  now: Date = new Date(),
): string[] {
  const fail = (msg: string): never => { throw new Error(`[x5c] ${msg}`); };
  const leaf = certs[0] ?? fail('certificate chain is empty');

  const key = issuerPublicKey instanceof KeyObject
    ? issuerPublicKey
    : KeyObject.from(issuerPublicKey as unknown as CryptoKey);
  if (!leaf.publicKey.equals(key)) {
    fail('the first certificate does not certify the current issuer key. Request a certificate for this key (or re-issue it after key rotation)');
  }
  if (leaf.ca) fail('the first certificate is a CA certificate; it must be the issuer (leaf) certificate');

  certs.forEach((c, i) => {
    if (isSelfSigned(c)) {
      fail(i === 0
        ? 'the issuer certificate is self-signed; wallets require one issued by a CA'
        : `certificate ${i} is self-signed (a trust anchor). Leave the root out of the chain`);
    }
    const next = certs[i + 1];
    if (next && !(c.checkIssued(next) && c.verify(next.publicKey))) {
      fail(`certificate ${i} is not issued by certificate ${i + 1}. Order the chain leaf first, then each issuer`);
    }
    if (now < new Date(c.validFrom) || now > new Date(c.validTo)) {
      fail(`certificate ${i} is not valid now (valid ${c.validFrom} to ${c.validTo})`);
    }
  });

  const url = stripSlash(issuerUrl);
  const host = new URL(url).hostname;
  const sans = (leaf.subjectAltName ?? '').split(/,\s*/);
  if (!sans.some(s => (s.startsWith('URI:') && stripSlash(s.slice(4)) === url) || s === `DNS:${host}`)) {
    fail(`the issuer certificate's subjectAltName (${leaf.subjectAltName ?? 'none'}) contains neither URI:${url} nor DNS:${host}`);
  }

  return certs.map(c => c.raw.toString('base64'));
}

let cached: { path: string; kid: string; certs: X509Certificate[] } | null = null;

/**
 * The `iss` value and optional `x5c` header to sign with. Re-validates on
 * every call (two signature checks) so expiry or key rotation is caught.
 */
export async function getIssuerSigningIdentity(config: VeriCredConfig): Promise<{ iss: string; x5c?: string[] }> {
  const path = config.issuer.certificateChain;
  if (!path) return { iss: config.issuer.did };

  // Public key from the active provider, so a non-exportable KMS/HSM key is
  // checked against the certificate the same way as the file key.
  const { publicKey: jwk, kid } = await getKeyProvider().getActiveKey();
  const publicKey = createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' });
  if (!cached || cached.path !== path || cached.kid !== kid) {
    cached = { path, kid, certs: parseCertificateChain(readFileSync(path, 'utf-8')) };
  }
  return { iss: config.issuer.url, x5c: validateCertificateChain(cached.certs, publicKey, config.issuer.url) };
}
