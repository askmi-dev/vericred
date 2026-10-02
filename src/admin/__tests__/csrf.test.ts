import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdirSync, existsSync, rmSync, writeFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';

describe('CSRF Protection Middleware', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;

  beforeAll(async () => {
    const tempDir = './src/admin/__tests__/temp-data-csrf';
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
    mkdirSync(tempDir, { recursive: true });

    const mockHolders = [
      { id: 'csrf-test-holder', email: 'csrf-test@example.com', firstName: 'CSRF', lastName: 'Test', dateOfBirth: '1990-01-01' }
    ];
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify(mockHolders, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['ISSUER_URL'] = 'http://localhost:3520';
    process.env['PORT'] = '3520';
    serverUrl = 'http://localhost:3520';

    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  afterAll(() => {
    const tempDir = './src/admin/__tests__/temp-data-csrf';
    if (existsSync(tempDir)) {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe('Bearer Token Auth (Server-to-Server)', () => {
    it('POST /admin/revoke with Bearer token and WITHOUT CSRF token returns 200 (CSRF skipped for Bearer)', async () => {
      // This test verifies that Bearer token auth bypasses CSRF requirement
      // Bearer tokens are for server-to-server, no CSRF context applicable
      const res = await fetch(`${serverUrl}/admin/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminApiKey}`
        },
        body: JSON.stringify({ credentialId: 'non-existent', reason: 'CSRF test' })
      });

      // Should succeed (200) because Bearer auth skips CSRF
      expect(res.status).toBe(200);
      const data = await res.json();
      // Will return success: false because credential doesn't exist, but NOT 403
      expect(data.success).toBe(false);
    });

    it('POST /admin/api/credentials/:id/revoke with Bearer token and WITHOUT CSRF returns 200', async () => {
      // Verify the new revocation endpoint also skips CSRF for Bearer
      const res = await fetch(`${serverUrl}/admin/api/credentials/test-cred-id/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${adminApiKey}`
        },
        body: JSON.stringify({ reason: 'Bearer CSRF bypass test' })
      });

      // Should return 404 (not found) or 200, but NEVER 403
      expect([200, 404]).toContain(res.status);
    });
  });

  describe('Session Cookie Auth (Browser-based)', () => {
    let sessionCookie: string;

    it('can login and get session cookie', async () => {
      // First, login to get a session cookie
      const loginRes = await fetch(`${serverUrl}/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ apiKey: adminApiKey }).toString(),
        redirect: 'manual'
      });

      expect(loginRes.status).toBe(302);
      const setCookieHeader = loginRes.headers.get('set-cookie');
      expect(setCookieHeader).toBeDefined();
      expect(setCookieHeader).toContain('admin_session=');
      
      // Extract the cookie value
      const cookieMatch = setCookieHeader?.match(/admin_session=([^;]+)/);
      expect(cookieMatch).toBeDefined();
      sessionCookie = cookieMatch![1];
    });

    it('GET /admin/api/csrf-handshake with session returns valid CSRF token', async () => {
      const res = await fetch(`${serverUrl}/admin/api/csrf-handshake`, {
        headers: { 'Cookie': `admin_session=${sessionCookie}` }
      });

      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.csrfToken).toBeDefined();
      expect(data.csrfToken).toBeTruthy();
      expect(typeof data.csrfToken).toBe('string');
      expect(data.csrfToken.length).toBeGreaterThan(20);
    });

    it('POST /admin/revoke with session cookie but WITHOUT x-csrf-token returns 403', async () => {
      // This is the main security test: session-based auth WITHOUT CSRF must fail
      const res = await fetch(`${serverUrl}/admin/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `admin_session=${sessionCookie}`
        },
        body: JSON.stringify({ credentialId: 'test-cred', reason: 'No CSRF token' })
      });

      // MUST return 403 Forbidden
      expect(res.status).toBe(403);
      const data = await res.json();
      expect(data.error).toBe('invalid csrf token');
    });

    it('POST /admin/api/credentials/:id/revoke with session cookie but WITHOUT x-csrf-token returns 403', async () => {
      const res = await fetch(`${serverUrl}/admin/api/credentials/test-id/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `admin_session=${sessionCookie}`
        },
        body: JSON.stringify({ reason: 'No CSRF token' })
      });

      expect(res.status).toBe(403);
      const data = await res.json();
      expect(data.error).toBe('invalid csrf token');
    });

    it('POST /admin/revoke with session cookie and INVALID x-csrf-token returns 403', async () => {
      const res = await fetch(`${serverUrl}/admin/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `admin_session=${sessionCookie}`,
          'x-csrf-token': 'invalid-token-12345'
        },
        body: JSON.stringify({ credentialId: 'test-cred', reason: 'Invalid CSRF' })
      });

      expect(res.status).toBe(403);
      const data = await res.json();
      expect(data.error).toBe('invalid csrf token');
    });

    it('POST /admin/revoke with session cookie and VALID x-csrf-token returns 200', async () => {
      // First, get a valid CSRF token
      const csrfRes = await fetch(`${serverUrl}/admin/api/csrf-handshake`, {
        headers: { 'Cookie': `admin_session=${sessionCookie}` }
      });
      
      expect(csrfRes.status).toBe(200);
      const csrfData = await csrfRes.json();
      const csrfToken = csrfData.csrfToken;

      // Now use it in a revocation request
      const res = await fetch(`${serverUrl}/admin/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `admin_session=${sessionCookie}`,
          'x-csrf-token': csrfToken
        },
        body: JSON.stringify({ credentialId: 'non-existent', reason: 'Valid CSRF test' })
      });

      // Should succeed (200) with valid CSRF
      expect(res.status).toBe(200);
      const data = await res.json();
      // Will return success: false because credential doesn't exist, but NOT 403
      expect(data.success).toBe(false);
    });

    it('POST /admin/api/credentials/:id/revoke with session cookie and VALID x-csrf-token returns 200', async () => {
      // Get valid CSRF token
      const csrfRes = await fetch(`${serverUrl}/admin/api/csrf-handshake`, {
        headers: { 'Cookie': `admin_session=${sessionCookie}` }
      });
      
      const csrfData = await csrfRes.json();
      const csrfToken = csrfData.csrfToken;

      // Use it for revocation
      const res = await fetch(`${serverUrl}/admin/api/credentials/test-cred-id/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `admin_session=${sessionCookie}`,
          'x-csrf-token': csrfToken
        },
        body: JSON.stringify({ reason: 'Valid CSRF test' })
      });

      // Should return 200 or 404, but NEVER 403
      expect([200, 404]).toContain(res.status);
    });
  });

  describe('CSRF Token Single-Use', () => {
    let sessionCookie: string;

    it('CSRF token can only be used once', async () => {
      // Login to get session
      const loginRes = await fetch(`${serverUrl}/admin/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ apiKey: adminApiKey }).toString(),
        redirect: 'manual'
      });

      const setCookieHeader = loginRes.headers.get('set-cookie');
      const cookieMatch = setCookieHeader?.match(/admin_session=([^;]+)/);
      sessionCookie = cookieMatch![1];

      // Get CSRF token
      const csrfRes = await fetch(`${serverUrl}/admin/api/csrf-handshake`, {
        headers: { 'Cookie': `admin_session=${sessionCookie}` }
      });
      const csrfData = await csrfRes.json();
      const csrfToken = csrfData.csrfToken;

      // First use - should work
      const res1 = await fetch(`${serverUrl}/admin/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `admin_session=${sessionCookie}`,
          'x-csrf-token': csrfToken
        },
        body: JSON.stringify({ credentialId: 'test-1', reason: 'First use' })
      });
      expect(res1.status).toBe(200);

      // Second use - should fail with 403
      const res2 = await fetch(`${serverUrl}/admin/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `admin_session=${sessionCookie}`,
          'x-csrf-token': csrfToken
        },
        body: JSON.stringify({ credentialId: 'test-2', reason: 'Second use' })
      });
      expect(res2.status).toBe(403);
    });
  });

  describe('Cache-Control Headers', () => {
    it('GET /admin/api/csrf-handshake has Cache-Control: no-store', async () => {
      const res = await fetch(`${serverUrl}/admin/api/csrf-handshake`, {
        headers: { 'Authorization': `Bearer ${adminApiKey}` }
      });

      expect(res.status).toBe(200);
      const cacheControl = res.headers.get('cache-control');
      expect(cacheControl).toContain('no-store');
      expect(cacheControl).toContain('no-cache');
      expect(cacheControl).toContain('must-revalidate');
      expect(cacheControl).toContain('max-age=0');
    });
  });
});
