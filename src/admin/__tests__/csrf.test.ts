import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';

describe('Session-Bound CSRF Integration', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;

  beforeAll(async () => {
    const tempDir = './src/admin/__tests__/temp-data-csrf';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
      {
        id: 'csrf-holder-01',
        firstName: 'Casey',
        lastName: 'Subject',
        email: 'casey.subject@example.com',
        region: 'Wien',
        timezone: 'Europe/Vienna',
        defaultPassword: 'derived-password',
        dateOfBirth: '1990-01-01',
        createdAt: new Date().toISOString(),
        sessionId: 'csrf-test'
      }
    ], null, 2));
    writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify({
      issuer: {
        name: 'VeriCred CSRF Test Issuer',
        url: 'http://localhost:3512',
        did: 'did:web:localhost%3A3512'
      },
      credential: { type: 'AgeCredential', expiresInDays: 30 },
      templateOptions: { ageThresholds: [18, 21], jurisdiction: 'EU' },
      dataSource: { type: 'json', path: `${tempDir}/holders.json` },
      fieldMappings: { dateOfBirth: 'dateOfBirth' }
    }, null, 2));

    // Set a custom port for CSRF tests to avoid conflicts
    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = '3512';
    process.env['ISSUER_URL'] = 'http://localhost:3512';
    serverUrl = 'http://localhost:3512';

    // Import server to spin up the instance
    await import('../../server.js');

    // Wait for server to start
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('blocks anonymous access to CSRF handshake endpoint', async () => {
    const res = await fetch(`${serverUrl}/admin/api/csrf-handshake`, {
      headers: { 'Accept': 'application/json' }
    });
    expect(res.status).toBe(401);
  });

  it('performs full session login, gets session-bound CSRF token, and validates cache control headers', async () => {
    // 1. Log in via POST /admin/login
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
    expect(setCookie).toContain('admin_session=');

    // Extract the admin_session cookie
    const cookiePart = setCookie!.split(';')[0];

    // 2. Fetch the session-bound CSRF handshake
    const handshakeRes = await fetch(`${serverUrl}/admin/api/csrf-handshake`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': cookiePart
      }
    });

    expect(handshakeRes.status).toBe(200);
    expect(handshakeRes.headers.get('cache-control')).toBe('no-store, no-cache, must-revalidate, max-age=0');

    const data = await handshakeRes.json() as { csrfToken: string };
    expect(data.csrfToken).toBeTruthy();
    expect(data.csrfToken.length).toBeGreaterThan(10);

    // 3. POST /admin/holder/password with missing CSRF should be forbidden
    const failNoCsrfRes = await fetch(`${serverUrl}/admin/holder/password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookiePart
      },
      body: JSON.stringify({ holderId: 'test', password: 'new-password' })
    });
    expect(failNoCsrfRes.status).toBe(403);
    const failData = await failNoCsrfRes.json() as Record<string, string>;
    expect(failData.error).toBe('invalid csrf token');

    // 4. POST /admin/holder/password with wrong CSRF should be forbidden
    const failWrongCsrfRes = await fetch(`${serverUrl}/admin/holder/password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookiePart,
        'x-csrf-token': 'wrong-token-here'
      },
      body: JSON.stringify({ holderId: 'test', password: 'new-password' })
    });
    expect(failWrongCsrfRes.status).toBe(403);

    // 5. POST /admin/holder/password with correct CSRF token should bypass CSRF and proceed to actual endpoint validation
    const successCsrfRes = await fetch(`${serverUrl}/admin/holder/password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookiePart,
        'x-csrf-token': data.csrfToken
      },
      body: JSON.stringify({ holderId: 'test', password: 'short' }) // triggers 400 Bad Request password length validation, proving CSRF bypassed!
    });
    expect(successCsrfRes.status).toBe(400);
    const successData = await successCsrfRes.json() as Record<string, string>;
    expect(successData.error).toBe('Password must be at least 8 characters');

    const holdersRes = await fetch(`${serverUrl}/admin/api/holders`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': cookiePart
      }
    });
    const holders = await holdersRes.json() as Array<{ id: string }>;
    expect(holders.length).toBeGreaterThan(0);

    const secondHandshakeRes = await fetch(`${serverUrl}/admin/api/csrf-handshake`, {
      headers: {
        'Accept': 'application/json',
        'Cookie': cookiePart
      }
    });
    const secondHandshake = await secondHandshakeRes.json() as { csrfToken: string };

    const passwordRes = await fetch(`${serverUrl}/admin/holder/password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookiePart,
        'x-csrf-token': secondHandshake.csrfToken
      },
      body: JSON.stringify({ holderId: holders[0].id, password: 'valid-password-123' })
    });
    expect(passwordRes.status).toBe(200);
    const passwordData = await passwordRes.json() as { success: boolean };
    expect(passwordData.success).toBe(true);
  });

  it('allows state-changing mutations with API bearer auth without CSRF token', async () => {
    const res = await fetch(`${serverUrl}/admin/holder/password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminApiKey}`
      },
      body: JSON.stringify({ holderId: 'test', password: 'short' })
    });
    // Triggers 400 Bad Request password validation instead of 403 Forbidden CSRF, proving CSRF bypassed for API clients!
    expect(res.status).toBe(400);
  });
});
