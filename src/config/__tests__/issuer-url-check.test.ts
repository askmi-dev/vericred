import { describe, it, expect, beforeEach, beforeAll, vi } from 'vitest';
import { request } from 'http';
import { mkdirSync, existsSync, rmSync, writeFileSync } from 'fs';
import {
  observedOrigin, noteMetadataRequest, getIssuerUrlStatus, startupIssuerUrlWarning,
  verifyIssuerUrlServesKey, resetIssuerUrlCheck,
} from '../issuer-url-check.js';

const PROD = 'https://vericred-production.up.railway.app';
const PREVIEW_HOST = 'vericred-pr-57.up.railway.app';

describe('observedOrigin', () => {
  it('uses the forwarded scheme and host a proxy reports', () => {
    expect(observedOrigin({ host: 'internal:8080', 'x-forwarded-host': PREVIEW_HOST, 'x-forwarded-proto': 'https' }, 'http'))
      .toBe(`https://${PREVIEW_HOST}`);
  });
  it('falls back to Host and the socket protocol, and normalises default ports', () => {
    expect(observedOrigin({ host: 'localhost:3100' }, 'http')).toBe('http://localhost:3100');
    expect(observedOrigin({ host: 'issuer.example:443', 'x-forwarded-proto': 'https' }, 'http')).toBe('https://issuer.example');
  });
  it('takes the first value of a proxy chain', () => {
    expect(observedOrigin({ host: 'a.example', 'x-forwarded-proto': 'https, http' }, 'http')).toBe('https://a.example');
  });
  it('ignores hosts that are not hostnames, so junk is never reported', () => {
    expect(observedOrigin({ host: 'evil.example/<script>' }, 'http')).toBeNull();
    expect(observedOrigin({}, 'http')).toBeNull();
    expect(observedOrigin({ host: 'a.example', 'x-forwarded-proto': 'javascript' }, 'https')).toBe('https://a.example');
  });
});

describe('metadata request tracking', () => {
  beforeEach(() => resetIssuerUrlCheck());

  it('is unchecked until a wallet fetches metadata, then ok on a match', () => {
    expect(getIssuerUrlStatus(PROD).status).toBe('unchecked');
    expect(noteMetadataRequest(PROD, PROD)).toBe(false);
    expect(getIssuerUrlStatus(PROD)).toEqual({ status: 'ok', configured: PROD });
  });

  it('reports a mismatch with the observed origin and logs each origin once', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    expect(noteMetadataRequest(PROD, `https://${PREVIEW_HOST}`)).toBe(true);
    noteMetadataRequest(PROD, `https://${PREVIEW_HOST}`);
    noteMetadataRequest(PROD, PROD); // a later match does not hide the mismatch
    const s = getIssuerUrlStatus(PROD);
    expect(s.status).toBe('mismatch');
    expect(s.status === 'mismatch' && s.observed).toBe(`https://${PREVIEW_HOST}`);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('caps logging so spoofed Host headers cannot flood the log', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    for (let i = 0; i < 100; i++) noteMetadataRequest(PROD, `https://spoof${i}.example`);
    expect(warn).toHaveBeenCalledTimes(20);
    warn.mockRestore();
  });

  it('starts over when issuer.url is changed (admin setup)', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    noteMetadataRequest(PROD, `https://${PREVIEW_HOST}`);
    expect(getIssuerUrlStatus(`https://${PREVIEW_HOST}`).status).toBe('unchecked');
    vi.restoreAllMocks();
  });
});

describe('startupIssuerUrlWarning', () => {
  it('flags a Railway deployment whose public domain is not issuer.url', () => {
    const w = startupIssuerUrlWarning(PROD, { RAILWAY_PUBLIC_DOMAIN: PREVIEW_HOST, RAILWAY_ENVIRONMENT_NAME: 'vericred-pr-57' });
    expect(w).toContain(PREVIEW_HOST);
    expect(w).toContain('vericred-pr-57');
    expect(w).toContain('RAILWAY_PUBLIC_DOMAIN');
  });
  it('is silent when they match, or off Railway', () => {
    expect(startupIssuerUrlWarning(PROD, { RAILWAY_PUBLIC_DOMAIN: new URL(PROD).host })).toBeNull();
    expect(startupIssuerUrlWarning(PROD, {})).toBeNull();
  });
});

describe('verifyIssuerUrlServesKey (CSR preflight)', () => {
  const key = { kid: 'k1', x: 'X', y: 'Y' };
  const stub = (meta: unknown, did: unknown) => async (url: string) => ({
    ok: true, status: 200,
    json: async () => (url.endsWith('/.well-known/did.json') ? did : meta),
  });
  const did = (kid: string, x = 'X', y = 'Y') => ({ verificationMethod: [{ publicKeyJwk: { kid, x, y } }] });

  it('passes when the deployment at issuer.url names itself and publishes this key', async () => {
    expect(await verifyIssuerUrlServesKey(PROD + '/', key, stub({ credential_issuer: PROD }, did('k1')))).toEqual([]);
  });

  it('refuses when issuer.url is another deployment with another key (inherited ISSUER_URL)', async () => {
    const problems = await verifyIssuerUrlServesKey(PROD, key, stub({ credential_issuer: PROD }, did('prod-key')));
    expect(problems.join()).toMatch(/does not publish this key/);
  });

  it('refuses a matching kid with different key material', async () => {
    const problems = await verifyIssuerUrlServesKey(PROD, key, stub({ credential_issuer: PROD }, did('k1', 'OTHER')));
    expect(problems.join()).toMatch(/does not publish this key/);
  });

  it('refuses metadata that names another issuer', async () => {
    const problems = await verifyIssuerUrlServesKey(PROD, key, stub({ credential_issuer: 'https://x.example' }, did('k1')));
    expect(problems.join()).toMatch(/names credential_issuer https:\/\/x\.example/);
  });

  it('refuses when issuer.url is unreachable', async () => {
    const down = async () => { throw new Error('ECONNREFUSED'); };
    expect((await verifyIssuerUrlServesKey(PROD, key, down)).join()).toMatch(/not reachable.*ECONNREFUSED/);
  });
});

describe('server: /health reports an issuer URL mismatch', () => {
  const PORT = 3524;
  const get = (path: string, headers: Record<string, string> = {}) => new Promise<{ status: number; body: any }>((resolve, reject) => {
    request({ host: '127.0.0.1', port: PORT, path, headers }, res => {
      let data = '';
      res.on('data', c => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode!, body: JSON.parse(data) }));
    }).on('error', reject).end();
  });

  beforeAll(async () => {
    const tempDir = './src/config/__tests__/temp-data-url-check';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(`${tempDir}/holders.json`, '[]');
    process.env['DATA_DIR'] = tempDir;
    process.env['ISSUER_URL'] = `http://localhost:${PORT}`;
    process.env['PORT'] = String(PORT);
    resetIssuerUrlCheck();
    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('is ok for the configured URL, mismatch after a request through another host, and stays HTTP 200', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    await get('/.well-known/openid-credential-issuer', { host: `localhost:${PORT}` });
    expect((await get('/health')).body.issuerUrl.status).toBe('ok');

    await get('/.well-known/openid-credential-issuer', { host: PREVIEW_HOST, 'x-forwarded-proto': 'https' });
    const health = await get('/health');
    expect(health.status).toBe(200);
    expect(health.body.status).toBe('ok');
    expect(health.body.issuerUrl).toMatchObject({
      status: 'mismatch', configured: `http://localhost:${PORT}`, observed: `https://${PREVIEW_HOST}`,
    });
    vi.restoreAllMocks();
  });
});
