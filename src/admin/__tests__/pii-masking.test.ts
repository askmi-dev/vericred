import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { loadSecrets } from '../../config/secrets.js';

describe('Administrative PII-Masking E2E Integration', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;

  beforeAll(async () => {
    // Set a custom port to avoid conflicts
    process.env['DATA_DIR'] = './data';
    process.env['PORT'] = '3514';
    serverUrl = 'http://localhost:3514';

    // Import server to spin up the instance
    await import('../../server.js');

    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  afterAll(() => {
    // Clean up environment variables
    delete process.env['PII_ADMIN_MODE'];
  });

  it('blocks unauthorized access to administrative JSON APIs', async () => {
    const resHolders = await fetch(`${serverUrl}/admin/api/holders`, {
      headers: { 'Accept': 'application/json' }
    });
    expect(resHolders.status).toBe(401);

    const resCreds = await fetch(`${serverUrl}/admin/api/credentials`, {
      headers: { 'Accept': 'application/json' }
    });
    expect(resCreds.status).toBe(401);
  });

  it('serves masked data by default when logged in', async () => {
    // Set environment mode to default (unset/false)
    process.env['PII_ADMIN_MODE'] = 'false';

    // Log in via POST /admin/login to get session
    const loginRes = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ apiKey: adminApiKey }).toString(),
      redirect: 'manual'
    });

    expect(loginRes.status).toBe(302);
    const setCookie = loginRes.headers.get('set-cookie');
    expect(setCookie).toBeTruthy();
    const cookiePart = setCookie!.split(';')[0];

    // Fetch holders API with session
    const holdersRes = await fetch(`${serverUrl}/admin/api/holders`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': cookiePart
      }
    });

    expect(holdersRes.status).toBe(200);
    const holders = await holdersRes.json() as any[];
    expect(holders.length).toBeGreaterThan(0);

    // Verify first holder is masked
    const firstHolder = holders[0];
    expect(firstHolder.firstName).toContain('***');
    expect(firstHolder.lastName).toContain('***');
    expect(firstHolder.email).toContain('***@');
    if (firstHolder.dateOfBirth) {
      expect(firstHolder.dateOfBirth).toBe('****-**-**');
    }
    expect(firstHolder.defaultPassword).toBeUndefined();
    expect(firstHolder.customPassword).toBeUndefined();

    // Fetch credentials API with session
    const credsRes = await fetch(`${serverUrl}/admin/api/credentials`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': cookiePart
      }
    });

    expect(credsRes.status).toBe(200);
    const credentials = await credsRes.json() as any[];
    if (credentials.length > 0) {
      expect(credentials[0].holderEmail).toContain('***@');
    }
  });

  it('serves unmasked, full data when PII_ADMIN_MODE is set to true', async () => {
    // Enable admin mode
    process.env['PII_ADMIN_MODE'] = 'true';

    // Log in via POST /admin/login to get session
    const loginRes = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ apiKey: adminApiKey }).toString(),
      redirect: 'manual'
    });

    expect(loginRes.status).toBe(302);
    const setCookie = loginRes.headers.get('set-cookie');
    expect(setCookie).toBeTruthy();
    const cookiePart = setCookie!.split(';')[0];

    // Fetch holders API
    const holdersRes = await fetch(`${serverUrl}/admin/api/holders`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': cookiePart
      }
    });

    expect(holdersRes.status).toBe(200);
    const holders = await holdersRes.json() as any[];
    expect(holders.length).toBeGreaterThan(0);

    // Verify first holder is NOT masked
    const firstHolder = holders[0];
    expect(firstHolder.firstName).not.toContain('***');
    expect(firstHolder.lastName).not.toContain('***');
    expect(firstHolder.email).not.toContain('***');
    expect(firstHolder.dateOfBirth).not.toBe('****-**-**');

    // Fetch credentials API
    const credsRes = await fetch(`${serverUrl}/admin/api/credentials`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': cookiePart
      }
    });

    expect(credsRes.status).toBe(200);
    const credentials = await credsRes.json() as any[];
    if (credentials.length > 0) {
      expect(credentials[0].holderEmail).not.toContain('***');
    }
  });
});
