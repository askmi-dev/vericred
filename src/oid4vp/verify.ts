import { createHash } from 'node:crypto';
import { importJWK, jwtVerify, type JWK } from 'jose';
import { getAllPublicKeys } from '../keys/manager.js';
import { credentialVct } from '../credentials/registry.js';
import { loadConfig } from '../config/loader.js';
import { getIssuedCredentials, isRetiredList } from '../revocation/statuslist.js';
import { getWalletProfile } from '../wallet/profile.js';

export const presentationProfiles: Record<string, string[]> = {
  AgeCredential: ['age_over_18'],
  EmployeeCredential: ['given_name', 'family_name', 'organization', 'role'],
  MembershipCredential: ['organization', 'membership_type'],
};

export type PresentationProtocol = 'openid4vp-1.0' | 'legacy-draft';
export async function verifyPresentation(token: unknown, nonce: string, audience: string, credentialType: string, protocol: PresentationProtocol = 'openid4vp-1.0') {
  if (typeof token !== 'string' || token.length > 100_000) throw new Error('Invalid presentation');
  const parts = token.split('~');
  const kbJwt = parts.pop();
  const issuerJwt = parts.shift();
  if (!issuerJwt || !kbJwt || !kbJwt.includes('.') || parts.some(p => !p || p.includes('.'))) throw new Error('Expected SD-JWT followed by key-binding JWT');
  const config = loadConfig();
  const eudi = getWalletProfile() === 'eudi-android';
  const legacy = protocol === 'legacy-draft';
  let payload;
  for (const key of await getAllPublicKeys()) {
    try {
      const verified = await jwtVerify(issuerJwt, await importJWK(key.publicKey, 'ES256'), {
        algorithms: ['ES256'], issuer: eudi ? config.issuer.url : config.issuer.did,
        requiredClaims: ['iss', 'iat', 'exp', 'jti', 'vct', 'cnf', '_sd', '_sd_alg', eudi ? 'status' : 'credentialStatus'],
      });
      if (!(legacy ? ['dc+sd-jwt', 'vc+sd-jwt'] : ['dc+sd-jwt']).includes(verified.protectedHeader.typ ?? '')) throw new Error('Invalid credential type');
      payload = verified.payload;
      break;
    } catch { /* Try retained public keys. */ }
  }
  if (!payload || typeof payload.vct !== 'string' || !(legacy ? [credentialVct(credentialType), credentialType] : [credentialVct(credentialType)]).includes(payload.vct) || payload._sd_alg !== 'sha-256') throw new Error('Untrusted credential or wrong profile');
  const digests = payload._sd;
  if (!Array.isArray(digests) || digests.some(d => typeof d !== 'string') || new Set(digests).size !== digests.length) throw new Error('Invalid commitments');
  const claims: Record<string, unknown> = Object.create(null);
  const seen = new Set<string>();
  for (const disclosure of parts) {
    const digest = createHash('sha256').update(disclosure, 'ascii').digest('base64url');
    if (!digests.includes(digest) || seen.has(digest)) throw new Error('Uncommitted or duplicate disclosure');
    seen.add(digest);
    const decoded: unknown = JSON.parse(Buffer.from(disclosure, 'base64url').toString('utf8'));
    if (!Array.isArray(decoded) || decoded.length !== 3 || typeof decoded[0] !== 'string' || typeof decoded[1] !== 'string') throw new Error('Malformed disclosure');
    const [, name, value] = decoded;
    if (Object.hasOwn(claims, name) || ['__proto__', 'constructor', 'prototype'].includes(name) || Object.hasOwn(payload, name)) throw new Error('Duplicate or reserved claim');
    claims[name] = value;
  }
  const jwk = (payload.cnf as { jwk?: JWK }).jwk;
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.d) throw new Error('Public P-256 holder binding required');
  const kb = await jwtVerify(kbJwt, await importJWK(jwk, 'ES256'), {
    algorithms: ['ES256'], typ: 'kb+jwt', audience, maxTokenAge: 300,
    clockTolerance: 30, requiredClaims: ['iat', 'nonce', 'aud', 'sd_hash'],
  });
  const presentedSdJwt = issuerJwt + '~' + (parts.length ? parts.join('~') + '~' : '');
  if (kb.payload.nonce !== nonce || kb.payload.sd_hash !== createHash('sha256').update(presentedSdJwt, 'ascii').digest('base64url')) throw new Error('Presentation binding mismatch');
  const entry = getIssuedCredentials().find(c => c.credentialId === payload.jti);
  if (!entry || entry.revoked || isRetiredList(entry.listId)) throw new Error('Unknown or revoked credential');
  if (eudi) {
    const status = payload.status as { status_list?: { idx?: unknown; uri?: unknown } };
    if (!status?.status_list || !Number.isInteger(status.status_list.idx) ||
        status.status_list.idx !== entry.statusIndex ||
        status.status_list.uri !== config.issuer.url + '/status/token/' + entry.listId) throw new Error('Invalid token status reference');
  } else {
    const status = payload.credentialStatus as Record<string, unknown>;
    if (!status || status.type !== 'StatusList2021Entry' || status.statusPurpose !== 'revocation' ||
        status.statusListIndex !== String(entry.statusIndex) ||
        status.statusListCredential !== config.issuer.url + '/status/' + entry.listId) throw new Error('Invalid credential status reference');
  }
  const required = presentationProfiles[credentialType];
  if (!required || required.some(name => !Object.hasOwn(claims, name))) throw new Error('Required claims were not disclosed');
  if (credentialType === 'AgeCredential' && claims.age_over_18 !== true) throw new Error('Age requirement not satisfied');
  return claims;
}
