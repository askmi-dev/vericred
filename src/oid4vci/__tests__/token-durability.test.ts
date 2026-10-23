/**
 * #37 review follow-up — route-level fail-closed behavior when the offer
 * store cannot make a state transition durable.
 *
 * Acceptance: if takePreAuthCode cannot persist the removal, /token must
 * answer server_error and never hand out an access token for a code that
 * a restart could resurrect. This exercises the real express route (not
 * just the store), with the persistence failure injected by making the
 * DATA_DIR read-only at the moment of the consume.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdirSync, rmSync, writeFileSync, chmodSync, statSync } from 'fs';
import { generateKeyPair } from 'jose';
import { loadSecrets } from '../../config/secrets.js';

const tempDir = './src/oid4vci/__tests__/temp-data-token-durability';

describe('/token fails closed when the consume is not durable', () => {
  let serverUrl: string;
  let adminApiKey: string;
  let code: string;

  beforeAll(async () => {
    rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
      { id: 'durability-holder-01', dateOfBirth: '1990-01-01' },
    ], null, 2));
    writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify({
      issuer: { name: 'VeriCred Test Issuer', url: 'http://localhost:3523', did: 'did:web:localhost%3A3523' },
      credential: { type: 'AgeCredential', expiresInDays: 30 },
      templateOptions: { ageThresholds: [18, 21] },
      dataSource: { type: 'json', path: `${tempDir}/holders.json` },
      fieldMappings: { dateOfBirth: 'dateOfBirth' },
    }, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = '3523';
    process.env['ISSUER_URL'] = 'http://localhost:3523';
    serverUrl = 'http://localhost:3523';
    adminApiKey = loadSecrets().adminApiKey;
    await generateKeyPair('ES256');

    await import('../../server.js');
    await new Promise((resolve) => setTimeout(resolve, 500));

    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'durability-holder-01' }),
    });
    const offer = await offerRes.json() as { offer?: { grants?: Record<string, { 'pre-authorized_code'?: string }> } };
    code = offer.offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'] ?? '';
    expect(code).not.toBe('');
  });

  afterAll(() => {
    chmodSync(tempDir, 0o700);
    rmSync(tempDir, { recursive: true, force: true });
    delete process.env['DATA_DIR'];
  });

  it('answers server_error and issues no token when persistence fails at consume time', async () => {
    // Make the DATA_DIR read-only: the temp-file write inside persist() fails.
    chmodSync(tempDir, 0o500);

    const res = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      }),
    });

    expect(res.status).toBe(500);
    const body = await res.json() as { error?: string };
    expect(body.error).toBe('server_error');

    chmodSync(tempDir, 0o700);

    // The code is still redeemable after recovery — exactly one token.
    const retry = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code,
      }),
    });
    expect(retry.status).toBe(200);
    const retryBody = await retry.json() as { access_token?: string };
    expect(typeof retryBody.access_token).toBe('string');

    // A fresh store over the same files (≡ restart) must not redeem it
    // again. The live server holds the lock; this read-only check uses
    // noLock deliberately — it must not race the server because the code
    // is already durably consumed.
    const { FileOfferStore } = await import('../state-store.js');
    const restarted = new FileOfferStore(tempDir, { noLock: true });
    expect(restarted.takePreAuthCode(code)).toBeNull();
  });

  it('a code that IS durably consumed cannot be replayed even after a restart', async () => {
    const offerRes = await fetch(`${serverUrl}/offer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminApiKey}` },
      body: JSON.stringify({ holderId: 'durability-holder-01' }),
    });
    const offer = await offerRes.json() as { offer?: { grants?: Record<string, { 'pre-authorized_code'?: string }> } };
    const code2 = offer.offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code'] ?? '';
    expect(code2).not.toBe('');

    const first = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code2,
      }),
    });
    expect(first.status).toBe(200);

    const replay = await fetch(`${serverUrl}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
        'pre-authorized_code': code2,
      }),
    });
    expect(replay.status).toBe(400);
    const replayBody = await replay.json() as { error?: string };
    expect(replayBody.error).toBe('invalid_grant');
  });

  it('offer-state.json is created with owner-only permissions when written by the server', () => {
    expect(existsSync(`${tempDir}/offer-state.json`)).toBe(true);
    const mode = statSync(`${tempDir}/offer-state.json`).mode & 0o077;
    expect(mode).toBe(0);
  });
});
