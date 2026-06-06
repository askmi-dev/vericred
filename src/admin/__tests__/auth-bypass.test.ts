import { describe, it, expect, beforeAll } from 'vitest';

describe('Auth Bypass Protection', () => {
  let serverUrl: string;

  beforeAll(async () => {
    // Set a custom port to avoid conflict
    process.env['PORT'] = '3511';
    serverUrl = 'http://localhost:3511';

    // Import server to spin up the instance
    await import('../../server.js');

    // Small delay to ensure server started listening
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('blocks unauthorized access to /console/dashboard', async () => {
    const res = await fetch(`${serverUrl}/console/dashboard`, {
      redirect: 'manual',
      headers: {
        'Accept': 'text/html'
      }
    });

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/admin/login');
  });

  it('blocks unauthorized access to /console/dashboard/index.html', async () => {
    const res = await fetch(`${serverUrl}/console/dashboard/index.html`, {
      redirect: 'manual',
      headers: {
        'Accept': 'text/html'
      }
    });

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/admin/login');
  });

  it('blocks unauthorized access to /console/legacy/blockchain', async () => {
    const res = await fetch(`${serverUrl}/console/legacy/blockchain`, {
      redirect: 'manual',
      headers: {
        'Accept': 'text/html'
      }
    });

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/admin/login');
  });

  it('blocks unauthorized API requests to /console/dashboard with JSON accept', async () => {
    const res = await fetch(`${serverUrl}/console/dashboard`, {
      headers: {
        'Accept': 'application/json'
      }
    });

    expect(res.status).toBe(401);
    const data = await res.json() as Record<string, string>;
    expect(data).toEqual({ error: 'unauthorized' });
  });

  it('allows access to public landing page', async () => {
    const res = await fetch(`${serverUrl}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('VeriCred');
  });
});
