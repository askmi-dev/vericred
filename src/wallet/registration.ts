import { z } from 'zod';
import { openSync, closeSync, fstatSync, readSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { decodeProtectedHeader, jwtVerify } from 'jose';

type Role = 'issuer' | 'verifier';
const maxBytes = 128 * 1024;
const algorithms = ['ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'];
const materialPath = (role: Role) => process.env[role === 'issuer' ? 'EUDI_ISSUER_REGISTRATION_CERT_PATH' : 'EUDI_VERIFIER_REGISTRATION_CERT_PATH'];

/** This controls gateway provisioning, not the wallet's own registration-policy switch. */
export function registrationRequired(): boolean {
  const policy = process.env.EUDI_REGISTRATION_POLICY ?? 'optional';
  if (policy !== 'optional' && policy !== 'required') throw new Error('Unsupported EUDI registration policy');
  return policy === 'required';
}

function readBounded(path: string): string {
  const fd = openSync(path, 'r');
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > maxBytes) throw new Error('Invalid registration material');
    const bytes = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (!count) break;
      length += count;
    }
    if (!length || length > maxBytes) throw new Error('Invalid registration material');
    return bytes.subarray(0, length).toString('utf8').trim();
  } finally { closeSync(fd); }
}

/**
 * JWT-only transport for the pinned Android contract. Checks local integrity and expiry only.
 * Embedded x5c is NOT a trust anchor. Provider trust, organization binding, live status,
 * entitlements and request/issuance scope remain wallet acceptance requirements.
 */
export async function registrationCertificate(role: Role) {
  const required = registrationRequired();
  const path = materialPath(role);
  if (!path) {
    if (required) throw new Error('Required registration material is not configured');
    return undefined;
  }
  try {
    const compact = readBounded(path);
    if (!/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(compact)) throw new Error();
    const header = decodeProtectedHeader(compact);
    if (header.typ !== 'rc-wrp+jwt' || !Array.isArray(header.x5c) || !header.x5c.length || header.x5c.length > 8) throw new Error();
    const chain = header.x5c.map(value => {
      if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error();
      return new X509Certificate(Buffer.from(value, 'base64'));
    });
    const now = Date.now();
    for (let index = 0; index < chain.length; index++) {
      const cert = chain[index];
      if (now < Date.parse(cert.validFrom) || now >= Date.parse(cert.validTo)) throw new Error();
      if (index + 1 < chain.length && (!chain[index + 1].ca || !cert.checkIssued(chain[index + 1]) ||
          !cert.verify(chain[index + 1].publicKey))) throw new Error();
    }
    if (chain[0].ca) throw new Error();
    const { payload } = await jwtVerify(compact, chain[0].publicKey, {
      algorithms, typ: 'rc-wrp+jwt', requiredClaims: ['sub', 'iat', 'exp', 'status'],
    });
    if (typeof payload.sub !== 'string' || !payload.sub.trim() || !Number.isSafeInteger(payload.iat) ||
        !Number.isSafeInteger(payload.exp) || payload.exp! <= payload.iat! || payload.iat! > Math.floor(now / 1000)) throw new Error();
    const status = payload.status as { status_list?: { idx?: unknown; uri?: unknown } } | undefined;
    const reference = status?.status_list;
    if (!reference || !Number.isSafeInteger(reference.idx) || (reference.idx as number) < 0 || (reference.idx as number) > 2147483647 || typeof reference.uri !== 'string') throw new Error();
    const uri = new URL(reference.uri);
    if (uri.protocol !== 'https:' || uri.username || uri.password || uri.hash) throw new Error();
    return { compact, expiresAt: new Date(Math.min(payload.exp! * 1000, ...chain.map(cert => Date.parse(cert.validTo)))).toISOString() };
  } catch { throw new Error('Registration material failed local validation'); }
}

/** Returns no token, path, identity claims or exception details to the admin UI. */
export async function inspectRegistration(role: Role) {
  const result: { configured: boolean; valid: boolean | null; expiresAt: string | null } = {
    configured: Boolean(materialPath(role)), valid: null, expiresAt: null,
  };
  if (!result.configured) return result;
  try {
    const certificate = await registrationCertificate(role);
    result.valid = Boolean(certificate);
    result.expiresAt = certificate?.expiresAt ?? null;
  } catch { result.valid = false; }
  return result;
}


// Local transport-shape checks only. Registrar provenance, registered scope and identity binding
// require independent acceptance. Preserve extension fields; never synthesize registered data.
const text = z.string().min(1).refine(value => value.trim().length > 0);
const uri = text.refine(value => { try { new URL(value); return !/\s/.test(value); } catch { return false; } });
const httpsUri = uri.refine(value => { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !url.hash; });
const localized = z.array(z.object({ lang: z.string().regex(/^[a-z]{2}$/), content: text }).passthrough()).min(1).max(128);
const object = z.record(z.unknown()).refine(value => Object.keys(value).length > 0);
const baseDataset = z.object({
  identifier: z.array(z.object({ type: uri, identifier: text }).passthrough()).min(1).max(128),
  srvDescription: localized,
  registryURI: httpsUri,
}).passthrough();
const issuerDataset = baseDataset.extend({
  providesAttestations: z.array(z.object({ format: text, type: uri }).passthrough()).min(1).max(256),
});
const verifierDataset = baseDataset.extend({
  intendedUseIdentifier: text, purpose: localized, policyURI: httpsUri,
  credential: z.array(z.object({ format: text, meta: object, claim: z.array(object).max(256).optional() }).passthrough()).max(256).optional(),
});
const datasetPath = (role: Role) => process.env[role === 'issuer' ? 'EUDI_ISSUER_REGISTRAR_DATASET_PATH' : 'EUDI_VERIFIER_REGISTRAR_DATASET_PATH'];

/** Reads only explicitly supplied files; no remote lookup and no inferred registration approval. */
export function registrarDataset(role: Role): Record<string, unknown> | undefined {
  const required = registrationRequired(), path = datasetPath(role);
  if (!path) {
    if (required) throw new Error('Required registrar dataset is not configured');
    return undefined;
  }
  try {
    const value: unknown = JSON.parse(readBounded(path));
    // Limit nesting and reject object mutation keys even in preserved extension data.
    const walk = (item: unknown, depth = 0): void => {
      if (depth > 16) throw new Error();
      if (item && typeof item === 'object') for (const [key, child] of Object.entries(item)) {
        if (['__proto__', 'prototype', 'constructor'].includes(key)) throw new Error();
        walk(child, depth + 1);
      }
    };
    walk(value);
    if (!value || typeof value !== 'object' || Array.isArray(value) || 'credential_ids' in value) throw new Error();
    (role === 'issuer' ? issuerDataset : verifierDataset).parse(value);
    return value as Record<string, unknown>;
  } catch { throw new Error('Registrar dataset failed local validation'); }
}

/** Returns no dataset, identifiers, paths, purposes or untrusted error text. */
export function inspectRegistrarDataset(role: Role) {
  const result: { configured: boolean; valid: boolean | null } = { configured: Boolean(datasetPath(role)), valid: null };
  if (!result.configured) return result;
  try { result.valid = Boolean(registrarDataset(role)); } catch { result.valid = false; }
  return result;
}

export async function registrationInfo(role: Role) {
  const certificate = await registrationCertificate(role);
  const dataset = registrarDataset(role);
  const info: { format: string; data: string | Record<string, unknown> }[] = [];
  if (certificate) info.push({ format: 'registration_cert', data: Buffer.from(certificate.compact, 'ascii').toString('base64url') });
  if (dataset) info.push({ format: 'registrar_dataset', data: dataset });
  return info.length ? info : undefined;
}
