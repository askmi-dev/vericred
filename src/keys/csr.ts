/**
 * PKCS#10 certificate signing request (RFC 2986) for the issuer key, so a
 * registrar CA can certify it for x5c. Encoded directly in DER: Node can
 * parse certificates but not build CSRs, and this keeps the private key in
 * process (no temp PEM file for openssl). ECDSA P-256 / SHA-256 only, which
 * is the only key type VeriCred issues with.
 */
import { sign, type KeyObject } from 'crypto';

export interface CsrSubject {
  commonName: string;
  organization?: string;
  /** ISO 3166 alpha-2, e.g. "DE" */
  country?: string;
}

export interface CsrRequest {
  privateKey: KeyObject;
  publicKey: KeyObject;
  subject: CsrSubject;
  sanUris?: string[];
  sanDns?: string[];
}

// ── Minimal DER encoder ─────────────────────────────────────────────────────
function derLength(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  for (let x = n; x > 0; x >>= 8) bytes.unshift(x & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag: number, ...parts: Buffer[]) => {
  const body = Buffer.concat(parts);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
};
const seq = (...p: Buffer[]) => tlv(0x30, ...p);
const set = (...p: Buffer[]) => tlv(0x31, ...p);
function oid(dotted: string): Buffer {
  const [a, b, ...rest] = dotted.split('.').map(Number) as [number, number, ...number[]];
  const out = [40 * a + b];
  for (const v of rest) {
    const chunk = [v & 0x7f];
    for (let x = v >> 7; x > 0; x >>= 7) chunk.unshift((x & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

const OID = {
  commonName: '2.5.4.3',
  country: '2.5.4.6',
  organization: '2.5.4.10',
  extensionRequest: '1.2.840.113549.1.9.14',
  subjectAltName: '2.5.29.17',
  ecdsaWithSha256: '1.2.840.10045.4.3.2',
};

const rdn = (type: string, value: Buffer) => set(seq(oid(type), value));
const utf8 = (s: string) => tlv(0x0c, Buffer.from(s, 'utf8'));
const ia5 = (s: string) => {
  if (!/^[\x00-\x7f]*$/.test(s)) throw new Error(`[csr] "${s}" must be ASCII (use punycode for IDNs)`);
  return Buffer.from(s, 'ascii');
};

export function buildCsr(req: CsrRequest): string {
  const { subject } = req;
  if (!subject.commonName.trim()) throw new Error('[csr] commonName is required');
  if (subject.country !== undefined && !/^[A-Z]{2}$/.test(subject.country)) {
    throw new Error('[csr] country must be a two-letter ISO code like "DE"');
  }
  if (req.publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    throw new Error('[csr] only P-256 issuer keys are supported');
  }

  const name = seq(
    ...(subject.country ? [rdn(OID.country, tlv(0x13, Buffer.from(subject.country, 'ascii')))] : []),
    ...(subject.organization ? [rdn(OID.organization, utf8(subject.organization))] : []),
    rdn(OID.commonName, utf8(subject.commonName)),
  );

  // GeneralNames: [6] uniformResourceIdentifier, [2] dNSName (IMPLICIT IA5String)
  const generalNames = [
    ...(req.sanUris ?? []).map(u => tlv(0x86, ia5(u))),
    ...(req.sanDns ?? []).map(d => tlv(0x82, ia5(d))),
  ];
  const attributes = generalNames.length === 0
    ? tlv(0xa0)
    : tlv(0xa0, seq(oid(OID.extensionRequest), set(seq(
        seq(oid(OID.subjectAltName), tlv(0x04, seq(...generalNames))),
      ))));

  const spki = req.publicKey.export({ type: 'spki', format: 'der' });
  const info = seq(Buffer.from([0x02, 0x01, 0x00]), name, spki, attributes);
  const signature = sign('sha256', info, req.privateKey); // DER-encoded ECDSA
  const der = seq(info, seq(oid(OID.ecdsaWithSha256)), tlv(0x03, Buffer.from([0x00]), signature));

  const b64 = der.toString('base64').match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN CERTIFICATE REQUEST-----\n${b64}\n-----END CERTIFICATE REQUEST-----\n`;
}
