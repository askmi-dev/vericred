import { registrarFixture } from './helpers/registrar-fixture.js';
import { attestationFixture } from './helpers/attestation-fixture.js';
import { beforeAll, afterAll, describe, expect, it, vi } from 'vitest';
import express from 'express';
import { createServer, type Server } from 'node:http';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync } from 'node:fs';
import { backupData, restoreData } from '../src/storage/recovery.js';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { SignJWT, CompactEncrypt, compactDecrypt, exportJWK, exportPKCS8, generateKeyPair, importJWK, jwtVerify } from 'jose';
import { loadConfig, saveConfig } from '../src/config/loader.js';
import { getIssuerKeyPair } from '../src/keys/manager.js';
import { createMetadataRouter } from '../src/oid4vci/metadata.js';
import { createCredentialRouter } from '../src/oid4vci/issuer.js';
import { createTokenRouter, issuePreAuthCode } from '../src/oid4vci/token.js';
import { createOid4vpRouter } from '../src/oid4vp/router.js';
import { createRevocationRouter } from '../src/revocation/router.js';
import { revokeCredential, getIssuedCredentials } from '../src/revocation/statuslist.js';
import { getWalletProfile, certificateSigner } from '../src/wallet/profile.js';
import { responseEncryption } from '../src/wallet/encryption.js';

const origin = 'https://vericred-test.example.invalid';
let base: string;
let server: Server;
let certificate: X509Certificate;
let walletStorageRevoked = false;
let attestation: Awaited<ReturnType<typeof attestationFixture>>;
const post = (body: unknown, token?: string) => ({ method: 'POST', headers: { 'Content-Type': 'application/json',
  ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: JSON.stringify(body) });
async function json(path: string, options?: RequestInit) {
  const response = await fetch(base + path, options);
  expect(response.ok).toBe(true);
  return response.json();
}
async function encrypt(body: unknown, jwk: any) {
  return new CompactEncrypt(Buffer.from(JSON.stringify(body)))
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: jwk.kid })
    .encrypt(await importJWK(jwk, 'ECDH-ES'));
}
beforeAll(async () => {
  const config = loadConfig();
  config.issuer = { name: 'Synthetic protocol fixture', url: origin, did: 'did:web:vericred-test.example.invalid' };
  config.credential = { type: 'AgeCredential', expiresInDays: 365, format: 'dc+sd-jwt' };
  config.fieldMappings = { dateOfBirth: 'dob' };
  saveConfig(config);
  const issuer = await getIssuerKeyPair();
  const dir = process.env.DATA_DIR!;
  const keyPath = join(dir, 'synthetic-signing.pem');
  const certPath = join(dir, 'synthetic-signing.crt');
  writeFileSync(keyPath, await exportPKCS8(issuer.privateKey), { mode: 0o600 });
  const bundled = 'C:/Program Files/Git/usr/bin/openssl.exe';
  const openssl = process.env.OPENSSL_BIN ?? (existsSync(bundled) ? bundled : 'openssl');
  execFileSync(openssl, ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '2',
    '-subj', '/CN=vericred-test.example.invalid', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature'], { stdio: 'pipe', windowsHide: true });
  certificate = new X509Certificate(readFileSync(certPath));
  attestation = await attestationFixture();
  const actualFetch = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: Parameters<typeof fetch>[0], options?: RequestInit) => {
    if (String(input) === attestation.statusUri) return new Response(await attestation.statusToken({}, Buffer.from([walletStorageRevoked ? 1 : 0])), { headers: { 'Content-Type': 'application/statuslist+jwt' } });
    return actualFetch(input, options);
  });
  process.env.WALLET_PROFILE = 'eudi-android';
  process.env.EUDI_ISSUER_CERT_CHAIN_PATH = certPath;
  process.env.EUDI_VERIFIER_CERT_CHAIN_PATH = certPath;
  process.env.EUDI_VERIFIER_KEY_PATH = keyPath;
  const app = express();
  app.use(express.json()); app.use(express.urlencoded({ extended: false }));
  app.use(createMetadataRouter()); app.use(createTokenRouter());
  app.use(createCredentialRouter(process.env.PSEUDO_SECRET!));
  app.use(createOid4vpRouter()); app.use(createRevocationRouter());
  server = createServer(app);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  base = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
});
afterAll(async () => { vi.unstubAllGlobals(); if (server) await new Promise<void>(resolve => server.close(() => resolve())); });

describe('EUDI protocol contract with synthetic certificates (not independent wallet acceptance)', () => {
  it('negotiates signed metadata and advertises encrypted final VCI', async () => {
    const response = await fetch(base + '/.well-known/openid-credential-issuer', { headers: { Accept: 'application/jwt' } });
    expect(response.headers.get('content-type')).toContain('application/jwt');
    const signed = await jwtVerify(await response.text(), certificate.publicKey, {
      algorithms: ['ES256'], typ: 'openidvci-issuer-metadata+jwt', subject: origin, issuer: origin,
    });
    expect(signed.protectedHeader.x5c?.[0]).toBe(certificate.raw.toString('base64'));
    const plain = await json('/.well-known/openid-credential-issuer', { headers: { Accept: 'application/json' } });
    expect(signed.payload.credential_configurations_supported).toEqual(plain.credential_configurations_supported);
    expect(plain.credential_request_encryption.jwks.keys[0]).toMatchObject({ alg: 'ECDH-ES', use: 'enc' });
    expect(plain.credential_response_encryption.encryption_required).toBe(true);
    expect(plain.credential_configurations_supported.AgeCredential.proof_types_supported.jwt.key_attestations_required).toMatchObject({ key_storage: ['iso_18045_high'], user_authentication: ['iso_18045_high'], preferred_key_storage_status_period: 365 * 86400 });
  });

  it('carries separately provisioned registration certificates in signed VCI and VP messages', async () => {
    const names = ['EUDI_ISSUER_REGISTRAR_DATASET_PATH', 'EUDI_VERIFIER_REGISTRAR_DATASET_PATH', 'EUDI_REGISTRATION_POLICY', 'EUDI_ISSUER_REGISTRATION_CERT_PATH', 'EUDI_VERIFIER_REGISTRATION_CERT_PATH'];
    const before = names.map(name => process.env[name]);
    try {
      const key = (await getIssuerKeyPair()).privateKey;
      const issue = async (sub: string) => new SignJWT({ sub, status: { status_list: { idx: 0, uri: 'https://registrar.example.invalid/status' } } })
        .setProtectedHeader({ alg: 'ES256', typ: 'rc-wrp+jwt', x5c: [certificate.raw.toString('base64')] })
        .setIssuedAt().setExpirationTime('5m').sign(key);
      const issuer = await issue('synthetic-issuer');
      const verifier = await issue('synthetic-verifier');
      process.env.EUDI_REGISTRATION_POLICY = 'required';
      for (const role of ['issuer', 'verifier'] as const) {
        const path = join(process.env.DATA_DIR!, role + '-registrar.json'); writeFileSync(path, JSON.stringify(registrarFixture(role)));
        process.env['EUDI_' + role.toUpperCase() + '_REGISTRAR_DATASET_PATH'] = path;
      }
      for (const [role, compact] of [['ISSUER', issuer], ['VERIFIER', verifier]]) {
        const path = join(process.env.DATA_DIR!, role + '-registration.jwt');
        writeFileSync(path, compact); process.env['EUDI_' + role + '_REGISTRATION_CERT_PATH'] = path;
      }
      const metadata = await jwtVerify(await (await fetch(base + '/.well-known/openid-credential-issuer', {
        headers: { Accept: 'application/jwt' },
      })).text(), certificate.publicKey);
      const expected = (compact: string, role: 'issuer' | 'verifier') => [{ format: 'registration_cert', data: Buffer.from(compact).toString('base64url') }, { format: 'registrar_dataset', data: registrarFixture(role) }];
      expect(metadata.payload.issuer_info).toEqual(expected(issuer, 'issuer'));
      const plain = await json('/.well-known/openid-credential-issuer', { headers: { Accept: 'application/json' } });
      expect(plain.issuer_info).toEqual(metadata.payload.issuer_info);
      const session = await json('/api/oid4vp/initiate', post({ credentialType: 'AgeCredential' }));
      const request = await jwtVerify(await (await fetch(base + '/api/oid4vp/request/' + session.sessionId)).text(), certificate.publicKey);
      expect(request.payload.verifier_info).toEqual(expected(verifier, 'verifier'));
      writeFileSync(process.env.EUDI_VERIFIER_REGISTRAR_DATASET_PATH!, '{}');
      expect((await fetch(base + '/api/oid4vp/request/' + session.sessionId)).status).toBe(503);
      writeFileSync(process.env.EUDI_VERIFIER_REGISTRAR_DATASET_PATH!, JSON.stringify(registrarFixture('verifier')));
      writeFileSync(process.env.EUDI_VERIFIER_REGISTRATION_CERT_PATH!, 'corrupt');
      expect((await fetch(base + '/api/oid4vp/request/' + session.sessionId)).status).toBe(503);
      delete process.env.EUDI_VERIFIER_REGISTRATION_CERT_PATH;
      expect((await fetch(base + '/api/oid4vp/initiate', post({ credentialType: 'AgeCredential' }))).status).toBe(503);
    } finally {
      names.forEach((name, index) => { if (before[index] === undefined) delete process.env[name]; else process.env[name] = before[index]; });
    }
  });

  it('rejects unsupported response encryption and accidental private keys', async () => {
    const pair = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const jwk = { ...await exportJWK(pair.publicKey), alg: 'ECDH-ES' };
    await expect(responseEncryption({ jwk, enc: 'A128CBC-HS256' })).rejects.toThrow();
    await expect(responseEncryption({ jwk: { ...await exportJWK(pair.privateKey), alg: 'ECDH-ES' }, enc: 'A128GCM' })).rejects.toThrow();
  });

  it('issues encrypted credentials, verifies encrypted selective presentations and publishes revocation', async () => {
    const metadata = await json('/.well-known/openid-credential-issuer', { headers: { Accept: 'application/json' } });
    const code = issuePreAuthCode({ id: 'synthetic-person', dob: '1990-01-01' }, 'AgeCredential');
    const token = await json('/token', post({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }));
    expect((await fetch(base + '/credentials', post({ credential_configuration_id: 'AgeCredential' }, token.access_token))).status).toBe(400);
    const holder = await generateKeyPair('ES256', { extractable: true });
    const nonce = await json('/nonce', post({}));
    const proof = await new SignJWT({ nonce: nonce.c_nonce }).setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', kid: '0', key_attestation: await attestation.attestation([await exportJWK(holder.publicKey)], nonce.c_nonce) })
      .setAudience(origin).setIssuedAt().sign(holder.privateKey);
    const responseKey = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const responseJwk = { ...await exportJWK(responseKey.publicKey), alg: 'ECDH-ES', kid: 'wallet-response' };
    const body = { credential_configuration_id: 'AgeCredential', proofs: { jwt: [proof] },
      credential_response_encryption: { jwk: responseJwk, enc: 'A128GCM' } };
    const encrypted = await encrypt(body, metadata.credential_request_encryption.jwks.keys[0]);
    const options = { method: 'POST', headers: { 'Content-Type': 'application/jwt', Authorization: 'Bearer ' + token.access_token }, body: encrypted };
    // Reject an ordinary embedded-JWK proof in the encrypted EUDI flow without consuming the grant.
    const untrustedProof = await new SignJWT({ nonce: nonce.c_nonce }).setAudience(origin).setIssuedAt()
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(holder.publicKey) }).sign(holder.privateKey);
    const untrustedBody = await encrypt({ ...body, proofs: { jwt: [untrustedProof] } }, metadata.credential_request_encryption.jwks.keys[0]);
    expect((await fetch(base + '/credentials', { ...options, body: untrustedBody })).status).toBe(400);
    walletStorageRevoked = true;
    try { expect((await fetch(base + '/credentials', options)).status).toBe(400); }
    finally { walletStorageRevoked = false; }
    const response = await fetch(base + '/credentials', options);
    expect(response.status).toBe(200); expect(response.headers.get('content-type')).toContain('application/jwt');
    const decoded = await compactDecrypt(await response.text(), responseKey.privateKey);
    const credential = JSON.parse(Buffer.from(decoded.plaintext).toString()).credentials[0].credential as string;
    expect((await fetch(base + '/credentials', options)).status).toBe(400);
    const pieces = credential.split('~').filter(Boolean);
    const issuerJwt = pieces.shift()!;
    const claims = (await jwtVerify(issuerJwt, certificate.publicKey, { issuer: origin, typ: 'dc+sd-jwt' })).payload;
    expect(claims.credentialStatus).toBeUndefined();
    const status = (claims.status as any).status_list;
    const disclosed = pieces.filter(value => JSON.parse(Buffer.from(value, 'base64url').toString())[1] === 'age_over_18');
    expect(disclosed).toHaveLength(1);
    const presented = issuerJwt + '~' + disclosed.join('~') + '~';
    const session = await json('/api/oid4vp/initiate', post({ credentialType: 'AgeCredential' }));
    const requestResponse = await fetch(base + '/api/oid4vp/request/' + session.sessionId);
    expect(requestResponse.headers.get('content-type')).toContain('application/oauth-authz-req+jwt');
    const request = (await jwtVerify(await requestResponse.text(), certificate.publicKey, {
      typ: 'oauth-authz-req+jwt', audience: 'https://self-issued.me/v2',
    })).payload as any;
    expect(request.response_mode).toBe('direct_post.jwt');
    expect(request.client_id).toBe('x509_hash:' + createHash('sha256').update(certificate.raw).digest('base64url'));
    const kb = await new SignJWT({ nonce: session.nonce, sd_hash: createHash('sha256').update(presented).digest('base64url') })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).setAudience(request.client_id).setIssuedAt().sign(holder.privateKey);
    const responseBody = { state: session.sessionId, vp_token: { credential: [presented + kb] } };
    expect((await fetch(base + '/api/oid4vp/response/' + session.sessionId, post(responseBody))).status).toBe(401);
    const encryptedPresentation = await encrypt(responseBody, request.client_metadata.jwks.keys[0]);
    const vpOptions = { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: encryptedPresentation }) };
    expect((await fetch(base + '/api/oid4vp/response/' + session.sessionId, vpOptions)).status).toBe(200);
    expect((await fetch(base + '/api/oid4vp/response/' + session.sessionId, vpOptions)).status).toBe(409);
    const verified = await json('/api/oid4vp/session/' + session.sessionId, { headers: { Authorization: 'Bearer ' + session.readToken } });
    expect(verified.claims).toEqual({ age_over_18: true });
    const statusPath = new URL(status.uri).pathname;
    async function bit() {
      const result = await fetch(base + statusPath);
      expect(result.headers.get('content-type')).toContain('application/statuslist+jwt');
      const jwt = await jwtVerify(await result.text(), certificate.publicKey, { typ: 'statuslist+jwt', issuer: origin, subject: status.uri });
      expect(jwt.payload.exp).toBeGreaterThan(jwt.payload.iat!);
      const list = jwt.payload.status_list as any;
      expect(list.bits).toBe(1);
      const bytes = inflateSync(Buffer.from(list.lst, 'base64url'));
      return (bytes[Math.floor(status.idx / 8)] >> (status.idx % 8)) & 1;
    }
    expect(await bit()).toBe(0);
    revokeCredential(claims.jti!);
    expect(await bit()).toBe(1);
    expect(getIssuedCredentials().find(value => value.credentialId === claims.jti)?.revoked).toBe(true);
    const retiredSession = await json('/api/oid4vp/initiate', post({ credentialType: 'AgeCredential' }));
    const retiredRequest = (await jwtVerify(await (await fetch(base + '/api/oid4vp/request/' + retiredSession.sessionId)).text(), certificate.publicKey)).payload as any;
    const revokedKb = await new SignJWT({ nonce: retiredSession.nonce, sd_hash: createHash('sha256').update(presented).digest('base64url') })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).setAudience(retiredRequest.client_id).setIssuedAt().sign(holder.privateKey);
    const revokedResponse = await encrypt({ state: retiredSession.sessionId, vp_token: { credential: [presented + revokedKb] } }, retiredRequest.client_metadata.jwks.keys[0]);
    expect((await fetch(base + '/api/oid4vp/response/' + retiredSession.sessionId, post({ response: revokedResponse }))).status).toBe(401);
  });

  it('rejects a certificate that does not match the configured verifier key', async () => {
    const original = process.env.EUDI_VERIFIER_KEY_PATH;
    const other = await generateKeyPair('ES256', { extractable: true });
    const path = join(process.env.DATA_DIR!, 'wrong-verifier.pem');
    writeFileSync(path, await exportPKCS8(other.privateKey));
    process.env.EUDI_VERIFIER_KEY_PATH = path;
    try { await expect(certificateSigner('verifier')).rejects.toThrow('match'); }
    finally { process.env.EUDI_VERIFIER_KEY_PATH = original; }
  });


  it('serves every old Token Status List index as revoked after an actual offline restore', async () => {
    const source = process.env.DATA_DIR!;
    const fixture = mkdtempSync(join(tmpdir(), 'vericred-eudi-restore-'));
    const oldList = getIssuedCredentials()[0].listId;
    const backup = join(fixture, 'backup');
    const restored = join(fixture, 'restored');
    await backupData(source, backup, process.env.PSEUDO_SECRET!);
    await restoreData(backup, restored, process.env.PSEUDO_SECRET!);
    process.env.DATA_DIR = restored;
    try {
      const response = await fetch(base + '/status/token/' + oldList);
      expect(response.status).toBe(200);
      const jwt = await jwtVerify(await response.text(), certificate.publicKey, { typ: 'statuslist+jwt', issuer: origin });
      const list = jwt.payload.status_list as any;
      expect(list.bits).toBe(1);
      expect(inflateSync(Buffer.from(list.lst, 'base64url')).every(byte => byte === 255)).toBe(true);
    } finally { process.env.DATA_DIR = source; }
  });

  it('does not silently fall back from an unknown profile', () => {
    process.env.WALLET_PROFILE = 'misspelled';
    try { expect(() => getWalletProfile()).toThrow(); }
    finally { process.env.WALLET_PROFILE = 'eudi-android'; }
  });
});
