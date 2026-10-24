import { describe, it, expect, beforeAll } from 'vitest';
import { loadSecrets } from '../../config/secrets.js';
import { createHmac } from 'crypto';

describe('Login CSRF Protection', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;

  beforeAll(async () => {
    process.env['PORT'] = '3521';
    serverUrl = 'http://localhost:3521';

    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  const getCsrfData = async () => {
    const res = await fetch(`${serverUrl}/admin/login`);
    const html = await res.text();
    const cookie = res.headers.get('set-cookie');
    const adminPre = cookie?.match(/admin_pre=([^;]+)/)?.[1] ?? '';
    const csrfToken = html.match(/name="csrf" value="([^"]+)"/)?.[1] ?? '';
    return { adminPre, csrfToken };
  };

  it('GET /admin/login issues admin_pre cookie and form with CSRF token', async () => {
    const res = await fetch(`${serverUrl}/admin/login`);
    expect(res.status).toBe(200);
    const setCookie = res.headers.get('set-cookie');
    expect(setCookie).toContain('admin_pre=');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('Path=/admin/login');
    expect(setCookie).toContain('SameSite=Strict');

    const html = await res.text();
    expect(html).toContain('name="csrf"');
  });

  it('POST /admin/login without CSRF token is rejected (403)', async () => {
    const res = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ apiKey: adminApiKey }).toString()
    });
    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe('missing csrf token');
  });

  it('POST /admin/login with token but without admin_pre cookie is rejected (403)', async () => {
    const { csrfToken } = await getCsrfData();
    const res = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ apiKey: adminApiKey, csrf: csrfToken }).toString()
    });
    expect(res.status).toBe(403);
  });

  it('POST /admin/login with token from different admin_pre is rejected', async () => {
    const data1 = await getCsrfData();
    const data2 = await getCsrfData();
    const res = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': `admin_pre=${data1.adminPre}`
      },
      body: new URLSearchParams({ apiKey: adminApiKey, csrf: data2.csrfToken }).toString()
    });
    expect(res.status).toBe(403);
    const result = await res.json();
    expect(result.error).toBe('invalid csrf token');
  });

  it('POST /admin/login with manipulated cookie is rejected', async () => {
    const { csrfToken } = await getCsrfData();
    const res = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': `admin_pre=manipulatedvalue1234567890abcdef`
      },
      body: new URLSearchParams({ apiKey: adminApiKey, csrf: csrfToken }).toString()
    });
    expect(res.status).toBe(403);
  });

  it('POST /admin/login with mismatched Origin header is rejected', async () => {
    const { adminPre, csrfToken } = await getCsrfData();
    const res = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': `admin_pre=${adminPre}`,
        'Origin': 'http://evil.com'
      },
      body: new URLSearchParams({ apiKey: adminApiKey, csrf: csrfToken }).toString()
    });
    expect(res.status).toBe(403);
    const result = await res.json();
    expect(result.error).toBe('invalid origin');
  });

  it('Valid flow: Redirects to dashboard, sets new session ID, clears admin_pre', async () => {
    const { adminPre, csrfToken } = await getCsrfData();
    const res = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': `admin_pre=${adminPre}`,
        'Host': 'localhost:3521',
        'Origin': 'http://localhost:3521'
      },
      body: new URLSearchParams({ apiKey: adminApiKey, csrf: csrfToken }).toString(),
      redirect: 'manual'
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/console/dashboard');

    const setCookies = res.headers.get('set-cookie');
    expect(setCookies).toContain('admin_session=');
    expect(setCookies).toContain('admin_pre=; HttpOnly; Path=/admin/login; Max-Age=0');
  });

  it('Invalid API key but valid CSRF token: Redirect to /admin/login?err=1, no session', async () => {
    const { adminPre, csrfToken } = await getCsrfData();
    const res = await fetch(`${serverUrl}/admin/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': `admin_pre=${adminPre}`
      },
      body: new URLSearchParams({ apiKey: 'wrong-key', csrf: csrfToken }).toString(),
      redirect: 'manual'
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/admin/login?err=1');
    const setCookies = res.headers.get('set-cookie');
    expect(setCookies).toBeNull(); // No new cookies should be set (or at least no admin_session)
  });
});
