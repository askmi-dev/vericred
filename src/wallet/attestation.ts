import { readFileSync, statSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { z } from 'zod';

const maxTokenBytes = 128 * 1024;
const maxBitmapBytes = 1024 * 1024;
const pin = z.string().regex(/^[a-fA-F0-9]{64}$/).transform(value => value.toLowerCase());
const assurance = z.enum(['iso_18045_high', 'iso_18045_moderate', 'iso_18045_enhanced-basic', 'iso_18045_basic']);
function httpsUrl(value: string): boolean {
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password && !url.hash && !url.search && !value.includes('\\') && !url.pathname.includes('%'); }
  catch { return false; }
}
const url = z.string().max(2048).refine(httpsUrl);
const providerSchema = z.object({
  id: z.string().min(1).max(100),
  signingCertificateSha256: z.array(pin).min(1).max(8),
  statusSigningCertificateSha256: z.array(pin).min(1).max(8),
  statusListPrefixes: z.array(url.refine(value => new URL(value).pathname.endsWith('/'))).min(1).max(8),
  keyStorage: z.array(assurance).min(1).max(4),
  userAuthentication: z.array(assurance).min(1).max(4),
  certifications: z.array(url).min(1).max(8),
}).strict();
const policySchema = z.object({
  version: z.literal(1),
  maxAttestationAgeSeconds: z.number().int().min(60).max(604800),
  maxStatusAgeSeconds: z.number().int().min(1).max(86400),
  providers: z.array(providerSchema).min(1).max(8),
}).strict().superRefine((policy, ctx) => {
  const pins = policy.providers.flatMap(provider => provider.signingCertificateSha256);
  if (new Set(pins).size !== pins.length || new Set(policy.providers.map(provider => provider.id)).size !== policy.providers.length) {
    ctx.addIssue({ code: 'custom', message: 'Ambiguous provider policy' });
  }
});
type Policy = z.infer<typeof policySchema>;
type Provider = z.infer<typeof providerSchema>;

/** Explicit deployment trust. No trust is learned from incoming JWTs or unverified discovery. */
export function loadAttestationPolicy(): Policy {
  try {
    const path = process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH;
    if (!path || !statSync(path).isFile() || statSync(path).size > maxTokenBytes) throw new Error();
    const data = readFileSync(path);
    if (data.length > maxTokenBytes) throw new Error();
    return policySchema.parse(JSON.parse(data.toString('utf8')));
  } catch { throw new Error('Wallet attestation policy is missing or invalid'); }
}
export function inspectAttestationPolicy() {
  const configured = Boolean(process.env.EUDI_WALLET_ATTESTATION_POLICY_PATH);
  try { return { configured, valid: true, providerCount: loadAttestationPolicy().providers.length }; }
  catch { return { configured, valid: false, providerCount: 0 }; }
}
export function attestationRequirements(credentialLifetimeSeconds: number) {
  const policy = loadAttestationPolicy();
  return { key_storage: [...new Set(policy.providers.flatMap(provider => provider.keyStorage))],
    user_authentication: [...new Set(policy.providers.flatMap(provider => provider.userAuthentication))],
    preferred_key_storage_status_period: credentialLifetimeSeconds };
}

function compactHeader(token: string, typ: string) {
  if (typeof token !== 'string' || token.length > maxTokenBytes || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new Error();
  const header = decodeProtectedHeader(token);
  if (header.typ !== typ || header.alg !== 'ES256' || header.jwk !== undefined || header.jku !== undefined || header.x5u !== undefined) throw new Error();
  if (!Array.isArray(header.x5c) || !header.x5c.length || header.x5c.length > 8) throw new Error();
  const chain = header.x5c.map(value => {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error();
    return new X509Certificate(Buffer.from(value, 'base64'));
  });
  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    if (Date.now() < Date.parse(cert.validFrom) || Date.now() >= Date.parse(cert.validTo)) throw new Error();
    if (i + 1 < chain.length && (!chain[i + 1].ca || !cert.checkIssued(chain[i + 1]) || !cert.verify(chain[i + 1].publicKey))) throw new Error();
  }
  const leaf = chain[0];
  const key = leaf.publicKey.export({ format: 'jwk' });
  if (leaf.ca || key.kty !== 'EC' || key.crv !== 'P-256') throw new Error();
  return { leaf, validUntil: Math.min(...chain.map(cert => Date.parse(cert.validTo))), fingerprint: createHash('sha256').update(leaf.raw).digest('hex') };
}
function numericDate(value: unknown): value is number { return Number.isSafeInteger(value) && (value as number) > 0; }
function allowedAssurance(value: unknown, allowed: string[]) {
  return Array.isArray(value) && value.length > 0 && value.length <= 4 && value.every(item => typeof item === 'string' && allowed.includes(item));
}
function reference(value: unknown, provider: Provider) {
  const list = (value as { status_list?: { idx?: unknown; uri?: unknown } } | undefined)?.status_list;
  if (!list || !Number.isSafeInteger(list.idx) || (list.idx as number) < 0 || (list.idx as number) > 2147483647 || typeof list.uri !== 'string' || !httpsUrl(list.uri)) throw new Error();
  const target = new URL(list.uri);
  if (!provider.statusListPrefixes.some(prefix => {
    const allowed = new URL(prefix);
    return target.origin === allowed.origin && target.pathname.startsWith(allowed.pathname);
  })) throw new Error();
  return { uri: target.href, idx: list.idx as number };
}
async function fetchStatusToken(uri: string): Promise<string> {
  // URLs are from an authenticated provider and constrained to its deployment-configured prefixes.
  // TLS stays enabled; no redirects, credentials, cookies, key discovery or cross-request cache.
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error();
  const response = await fetch(uri, { headers: { Accept: 'application/statuslist+jwt' }, redirect: 'error',
    credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(10000) });
  if (response.status !== 200 || !/^application\/statuslist\+jwt(?:;|$)/i.test(response.headers.get('content-type') ?? '') || !response.body) {
    await response.body?.cancel(); throw new Error();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = []; let length = 0;
  try {
    for (;;) {
      const result = await reader.read(); if (result.done) break;
      length += result.value.length; if (length > maxTokenBytes) throw new Error();
      chunks.push(result.value);
    }
  } finally { await reader.cancel(); }
  return Buffer.concat(chunks).toString('utf8');
}
async function checkStatus(ref: { uri: string; idx: number }, provider: Provider, policy: Policy) {
  const token = await fetchStatusToken(ref.uri);
  const signer = compactHeader(token, 'statuslist+jwt');
  if (!provider.statusSigningCertificateSha256.includes(signer.fingerprint)) throw new Error();
  const { payload } = await jwtVerify(token, signer.leaf.publicKey, {
    algorithms: ['ES256'], typ: 'statuslist+jwt', subject: ref.uri, requiredClaims: ['sub', 'iat', 'exp', 'status_list'],
  });
  const now = Math.floor(Date.now() / 1000);
  if (!numericDate(payload.iat) || !numericDate(payload.exp) || payload.iat > now + 30 || payload.exp <= payload.iat || now - payload.iat > policy.maxStatusAgeSeconds) throw new Error();
  if (payload.ttl !== undefined && (!numericDate(payload.ttl) || now >= payload.iat + payload.ttl)) throw new Error();
  const list = payload.status_list as { bits?: unknown; lst?: unknown };
  if (!list || ![1, 2, 4, 8].includes(list.bits as number) || typeof list.lst !== 'string' || !/^[A-Za-z0-9_-]+$/.test(list.lst)) throw new Error();
  const bytes = inflateSync(Buffer.from(list.lst, 'base64url'), { maxOutputLength: maxBitmapBytes });
  const bits = list.bits as number;
  const bitIndex = ref.idx * bits;
  if (Math.floor(bitIndex / 8) >= bytes.length) throw new Error();
  // Token Status List is LSB-first; only status 0 is accepted. Suspended/unknown codes fail closed.
  if (((bytes[Math.floor(bitIndex / 8)] >> (bitIndex % 8)) & ((1 << bits) - 1)) !== 0) throw new Error();
  // Keep the earliest deadline so an earlier status cannot go stale while another is fetched.
  // The max-age check above accepts the whole second at the configured age boundary.
  return Math.min(signer.validUntil, payload.exp * 1000,
    (payload.iat + policy.maxStatusAgeSeconds + 1) * 1000,
    payload.ttl === undefined ? Infinity : (payload.iat + (payload.ttl as number)) * 1000);
}

/** Authenticate provider and attested keys before exposing a key to the outer PoP verifier. */
export async function validateKeyAttestation(token: string, expectedNonce: string, credentialLifetimeSeconds: number) {
  try {
    if (!Number.isSafeInteger(credentialLifetimeSeconds) || credentialLifetimeSeconds <= 0) throw new Error();
    const policy = loadAttestationPolicy();
    const signer = compactHeader(token, 'key-attestation+jwt');
    const provider = policy.providers.find(item => item.signingCertificateSha256.includes(signer.fingerprint));
    if (!provider) throw new Error();
    const { payload } = await jwtVerify(token, signer.leaf.publicKey, {
      algorithms: ['ES256'], typ: 'key-attestation+jwt', requiredClaims: ['iat', 'exp', 'attested_keys', 'key_storage', 'user_authentication', 'certification', 'key_storage_status'],
    });
    const now = Math.floor(Date.now() / 1000);
    if (!numericDate(payload.iat) || !numericDate(payload.exp) || payload.iat > now + 30 || payload.exp <= payload.iat || now - payload.iat > policy.maxAttestationAgeSeconds) throw new Error();
    // For JWT proof, outer nonce is mandatory; if the KA supplies a nonce it must agree.
    if (payload.nonce !== undefined && payload.nonce !== expectedNonce) throw new Error();
    if (!allowedAssurance(payload.key_storage, provider.keyStorage) || !allowedAssurance(payload.user_authentication, provider.userAuthentication) ||
        typeof payload.certification !== 'string' || !provider.certifications.includes(payload.certification)) throw new Error();
    if (!Array.isArray(payload.attested_keys) || !payload.attested_keys.length || payload.attested_keys.length > 8) throw new Error();
    const keys: JWK[] = [];
    for (const value of payload.attested_keys) {
      const jwk = value as JWK;
      if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d !== undefined || (jwk.alg !== undefined && jwk.alg !== 'ES256') ||
          (jwk.use !== undefined && jwk.use !== 'sig') || (jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops) || jwk.key_ops.some(op => op !== 'verify')))) throw new Error();
      const publicKey: JWK = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
      await importJWK(publicKey, 'ES256'); keys.push(publicKey);
    }
    const storage = payload.key_storage_status as { status?: unknown; exp?: unknown };
    if (!storage || !numericDate(storage.exp) || storage.exp < now + credentialLifetimeSeconds) throw new Error();
    const refs = [reference(storage.status, provider)];
    if (payload.status !== undefined) refs.push(reference(payload.status, provider));
    const storageExpiresAt = storage.exp;
    return { jwk: keys[0], storageExpiresAt,
      // Call only after the outer proof's signature/audience/time/nonce passed.
      verifyStatus: async () => {
        try {
          const statusValidUntil: number[] = [];
          for (const ref of refs) statusValidUntil.push(await checkStatus(ref, provider, policy));
          const checkedAt = Date.now();
          if (checkedAt >= signer.validUntil || checkedAt >= payload.exp! * 1000 ||
              Math.floor(checkedAt / 1000) - payload.iat! > policy.maxAttestationAgeSeconds ||
              statusValidUntil.some(validUntil => checkedAt >= validUntil) ||
              JSON.stringify(loadAttestationPolicy()) !== JSON.stringify(policy)) throw new Error();
        }
        catch { throw new Error('Wallet key attestation status could not be validated'); }
      },
    };
  } catch { throw new Error('Wallet key attestation could not be validated'); }
}
