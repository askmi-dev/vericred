import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import express from 'express';
import type { Server } from 'node:http';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { SignJWT, generateKeyPair, exportJWK, decodeJwt } from 'jose';
import { ConfigConflictError, DEFAULT_CONFIG, loadConfig, saveConfig } from '../loader.js';
import { resolveTemplateConfig, selectTemplate } from '../template.js';
import { createAdminRouter } from '../../admin/router.js';
import * as connectors from '../../connectors/index.js';
import { createOfferRouter } from '../../oid4vci/offer.js';
import { createMetadataRouter } from '../../oid4vci/metadata.js';
import { createTokenRouter, issuePreAuthCode, lookupAccessToken } from '../../oid4vci/token.js';
import { createCredentialRouter } from '../../oid4vci/issuer.js';
import { assignStatusIndex } from '../../revocation/statuslist.js';
import { EncryptedMap } from '../../storage/encrypted-map.js';

const baseDataDir = process.env.DATA_DIR!;
const previousWalletProfile = process.env.WALLET_PROFILE;
const employeeMapping = { given_name: 'first', family_name: 'last', organization: 'org', role: 'role' };
const holder = { id: 'synthetic-holder', dateOfBirth: '1990-01-01' };
const grantType = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
let servers: Server[] = [];
async function listen(app: express.Express) {
  const server = await new Promise<Server>(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
  servers.push(server);
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected listener');
  return 'http://127.0.0.1:' + address.port;
}
function post(base: string, path: string, body: unknown, token = process.env.ADMIN_API_KEY) {
  return fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body: JSON.stringify(body) });
}
function appWithAdmin() {
  const app = express(); app.use(express.json());
  app.use(createAdminRouter({ lookup: async () => holder, getSchema: async () => ['dateOfBirth'] }));
  return app;
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}

beforeEach(() => {
  process.env.WALLET_PROFILE = 'custom';
  process.env.DATA_DIR = mkdtempSync(join(baseDataDir, 'config-case-'));
  const sourcePath = join(process.env.DATA_DIR, 'holders.json');
  writeFileSync(sourcePath, JSON.stringify([holder]));
  saveConfig({ ...structuredClone(DEFAULT_CONFIG), issuer: { name: 'Test issuer', url: 'https://issuer.example', did: 'did:web:issuer.example' }, dataSource: { type: 'json', path: sourcePath } });
});
afterEach(async () => {
  await Promise.all(servers.map(server => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))));
  servers = []; vi.restoreAllMocks(); process.env.DATA_DIR = baseDataDir;
  if (previousWalletProfile === undefined) delete process.env.WALLET_PROFILE; else process.env.WALLET_PROFILE = previousWalletProfile;
});

describe('Configuration generations and grant policy snapshots', () => {
  it('rejects a stale compare-and-swap without losing the newer mapping', () => {
    const stale = loadConfig();
    const latest = loadConfig(); latest.fieldMappings = { dateOfBirth: 'birth_date' };
    const saved = saveConfig(latest);
    stale.issuer.name = 'Stale setup';
    expect(() => saveConfig(stale)).toThrow(ConfigConflictError);
    expect(loadConfig().fieldMappings).toEqual({ dateOfBirth: 'birth_date' });
    expect(loadConfig().revision).toBe(saved.revision);
  });

  it('rejects an async setup probe that would overwrite a newer mapping', async () => {
    const entered = deferred(); const release = deferred(); const close = vi.fn();
    vi.spyOn(connectors, 'buildConnector').mockReturnValue({ lookup: async () => holder, getSchema: async () => [], healthCheck: async () => { entered.resolve(); await release.promise; }, close });
    const base = await listen(appWithAdmin());
    const initial = loadConfig();
    const setup = post(base, '/admin/api/setup', { name: 'Stale setup', url: initial.issuer.url, revision: initial.revision });
    await entered.promise;
    const mapping = await post(base, '/admin/api/save-mapping', { templateId: 'EmployeeCredential', fieldMappings: employeeMapping, revision: initial.revision });
    expect(mapping.status).toBe(200);
    release.resolve();
    const result = await setup;
    expect(result.status).toBe(409);
    expect(await result.json()).toMatchObject({ error: 'configuration_changed' });
    expect(loadConfig().credential.type).toBe('EmployeeCredential');
    expect(loadConfig().issuer.name).toBe(initial.issuer.name);
    expect(close).toHaveBeenCalledOnce();
  });

  it('rejects stale client revisions even when no setup probe overlaps', async () => {
    const base = await listen(appWithAdmin());
    const staleRevision = loadConfig().revision;
    const current = loadConfig(); current.issuer.name = 'New name'; saveConfig(current);
    const response = await post(base, '/admin/api/save-mapping', { templateId: 'EmployeeCredential', fieldMappings: employeeMapping, revision: staleRevision });
    expect(response.status).toBe(409);
    expect(loadConfig().credential.type).toBe('AgeCredential');
  });

  it('rejects an offer if configuration changes and changes back during holder lookup', async () => {
    const entered = deferred(); const release = deferred();
    const app = express(); app.use(express.json());
    app.use(createOfferRouter(async () => { entered.resolve(); await release.promise; return holder; }));
    const base = await listen(app);
    const request = post(base, '/offer', { holderId: holder.id });
    await entered.promise;
    const original = loadConfig(); const changed = { ...original, issuer: { ...original.issuer, name: 'Temporary name' } };
    saveConfig(changed);
    saveConfig({ ...original, revision: loadConfig().revision });
    release.resolve();
    const response = await request;
    expect(response.status).toBe(409);
    expect(existsSync(join(process.env.DATA_DIR!, 'preauth-codes.encrypted.json'))).toBe(false);
  });

  it('keeps prior Age options aligned between metadata and grants after selecting Employee', async () => {
    const config = loadConfig(); config.templateOptions = { ageThresholds: [18], jurisdiction: 'AT' }; saveConfig(config);
    const next = loadConfig(); selectTemplate(next, 'EmployeeCredential', employeeMapping); saveConfig(next);
    const current = loadConfig();
    expect(resolveTemplateConfig(current, 'AgeCredential').templateOptions).toEqual({ ageThresholds: [18], jurisdiction: 'AT' });
    expect(resolveTemplateConfig(current, 'EmployeeCredential').templateOptions).toEqual({});
    const app = express(); app.use(express.json()); app.use(createMetadataRouter()); app.use(createTokenRouter());
    const base = await listen(app);
    const metadata = await (await fetch(base + '/.well-known/openid-credential-issuer')).json() as any;
    const paths = metadata.credential_configurations_supported.AgeCredential.credential_metadata.claims.map((claim: any) => claim.path[0]);
    expect(paths).toEqual(['age_over_18', 'age_attested_at', 'jurisdiction']);
    const code = issuePreAuthCode(holder, 'AgeCredential');
    const response = await post(base, '/token', { grant_type: grantType, 'pre-authorized_code': code });
    expect(response.status).toBe(200);
    const token = await response.json() as any;
    expect(lookupAccessToken(token.access_token)?.templateOptions).toEqual({ ageThresholds: [18], jurisdiction: 'AT' });
  });

  it('keeps explicit default options, format, mappings and lifetime frozen through issuance', async () => {
    const config = loadConfig(); delete config.templateOptions; saveConfig(config);
    const app = express(); app.use(express.json()); app.use(createTokenRouter()); app.use(createCredentialRouter('test-pseudonym-secret'));
    const base = await listen(app);
    const code = issuePreAuthCode(holder, 'AgeCredential');
    const response = await post(base, '/token', { grant_type: grantType, 'pre-authorized_code': code });
    const token = await response.json() as any;
    expect(lookupAccessToken(token.access_token)?.templateOptions).toEqual({});
    const changed = loadConfig(); changed.templateOptions = { ageThresholds: [21] }; changed.fieldMappings = { dateOfBirth: 'other_field' }; changed.credential.expiresInDays = 1; changed.credential.format = 'vc+sd-jwt'; saveConfig(changed);
    const keys = await generateKeyPair('ES256');
    const proof = await new SignJWT({ nonce: token.c_nonce }).setAudience(config.issuer.url).setIssuedAt()
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await exportJWK(keys.publicKey) }).sign(keys.privateKey);
    const issued = await post(base, '/credentials', { format: 'dc+sd-jwt', proof: { proof_type: 'jwt', jwt: proof } }, token.access_token);
    expect(issued.status).toBe(200);
    const body = await issued.json() as any;
    const [jwt, ...parts] = body.credential.split('~');
    const claims = Object.fromEntries(parts.filter(Boolean).map((value: string) => JSON.parse(Buffer.from(value, 'base64url').toString()).slice(1)));
    expect(claims.age_over_18).toBe(true); expect(claims.age_over_21).toBe(true);
    expect(body.format).toBe('dc+sd-jwt');
    const payload = decodeJwt(jwt); expect(payload.exp! - payload.iat!).toBe(30 * 86400);
  });

  it('invalidates a pending grant when issuer authority changes', async () => {
    const app = express(); app.use(express.json()); app.use(createTokenRouter()); const base = await listen(app);
    const code = issuePreAuthCode(holder);
    const config = loadConfig(); config.issuer = { ...config.issuer, url: 'https://other.example', did: 'did:web:other.example' }; saveConfig(config);
    const response = await post(base, '/token', { grant_type: grantType, 'pre-authorized_code': code });
    expect(response.status).toBe(400); expect(await response.json()).toEqual({ error: 'invalid_grant' });
  });

  it('invalidates a grant when the selected runtime wallet profile changes', async () => {
    const app = express(); app.use(express.json()); app.use(createTokenRouter()); const base = await listen(app);
    const code = issuePreAuthCode(holder);
    process.env.WALLET_PROFILE = 'eudi-android';
    const response = await post(base, '/token', { grant_type: grantType, 'pre-authorized_code': code });
    expect(response.status).toBe(400); expect(await response.json()).toEqual({ error: 'invalid_grant' });
  });

  it('blocks uncoordinated issuer-key rotation in the EUDI wallet profile', async () => {
    const base = await listen(appWithAdmin()); process.env.WALLET_PROFILE = 'eudi-android';
    const response = await post(base, '/admin/api/rotate-keys', {});
    expect(response.status).toBe(409); expect(await response.json()).toMatchObject({ error: 'certificate_rotation_required' });
    expect(existsSync(join(process.env.DATA_DIR!, 'keys'))).toBe(false);
  });

  it('fails closed on old persisted grants that lack policy snapshots', async () => {
    new EncryptedMap<any>('access-tokens').set('old-token', { holderData: holder, expiresAt: Date.now() + 60_000, cNonce: 'nonce', cNonceExpiresAt: Date.now() + 60_000 });
    expect(lookupAccessToken('old-token')).toBeNull();
  });

  it('requires issuer migration after issuance while allowing name and source updates', async () => {
    const base = await listen(appWithAdmin());
    const initial = loadConfig(); assignStatusIndex('test-issued', holder.id, 'AgeCredential');
    const changedAuthority = await post(base, '/admin/api/setup', { name: 'Changed issuer', url: 'https://other.example' });
    expect(changedAuthority.status).toBe(409);
    expect(await changedAuthority.json()).toMatchObject({ error: 'issuer_migration_required' });
    expect(loadConfig().issuer).toEqual(initial.issuer);
    const source = join(process.env.DATA_DIR!, 'replacement-holders.json'); writeFileSync(source, JSON.stringify([holder]));
    const changedNameAndSource = await post(base, '/admin/api/setup', { name: 'Renamed issuer', url: initial.issuer.url, dataSource: { type: 'json', path: source } });
    expect(changedNameAndSource.status).toBe(200);
    expect(loadConfig().issuer.name).toBe('Renamed issuer'); expect(loadConfig().dataSource.path).toBe(source);
  });
});
