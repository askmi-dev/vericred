import { describe, it, expect, vi, afterEach } from 'vitest';
import { adminMutation, escapeHtml } from '../stitch-out/src/admin-client.js';

describe('Admin browser client', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('escapes wallet-controlled text for both HTML text and quoted attributes', () => {
    const attack = '<img src=x onerror="alert(1)"> & \' autofocus onfocus=alert(2)';
    const escaped = escapeHtml(attack);
    expect(escaped).toBe('&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; &#39; autofocus onfocus=alert(2)');
    expect(escaped).not.toMatch(/[<>"']/);
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
  });
  it('requests a fresh token for every mutation and overwrites stale caller tokens', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(Response.json({ csrfToken: 'first' }))
      .mockResolvedValueOnce(Response.json({ success: true }))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'second' }))
      .mockResolvedValueOnce(Response.json({ success: true }));
    vi.stubGlobal('fetch', fetch);
    const options = { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-csrf-token': 'stale' }, body: '{"value":1}' };
    await adminMutation('/admin/action', options);
    await adminMutation('/admin/action', options);
    expect(fetch).toHaveBeenNthCalledWith(1, '/admin/api/csrf-handshake', { credentials: 'same-origin', cache: 'no-store' });
    expect(fetch).toHaveBeenNthCalledWith(3, '/admin/api/csrf-handshake', { credentials: 'same-origin', cache: 'no-store' });
    const first = fetch.mock.calls[1][1] as RequestInit;
    const second = fetch.mock.calls[3][1] as RequestInit;
    expect(new Headers(first.headers).get('x-csrf-token')).toBe('first');
    expect(new Headers(second.headers).get('x-csrf-token')).toBe('second');
    expect(first.body).toBe(options.body);
    expect(first.credentials).toBe('same-origin');
    expect(options.headers['x-csrf-token']).toBe('stale');
  });
  it.each([
    [401, { error: 'unauthorized' }, 'session has expired'],
    [200, { csrfToken: '' }, 'Could not authorize'],
    [200, { csrfToken: 42 }, 'Could not authorize'],
  ])('does not send the mutation when the handshake is invalid (%s)', async (status, body, message) => {
    const fetch = vi.fn().mockResolvedValue(Response.json(body, { status }));
    vi.stubGlobal('fetch', fetch);
    await expect(adminMutation('/admin/action', { method: 'POST' })).rejects.toThrow(message);
    expect(fetch).toHaveBeenCalledOnce();
  });
  it('keeps tokens separate for concurrent actions', async () => {
    let handshakes = 0;
    const tokens: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit) => {
      if (url === '/admin/api/csrf-handshake') return Response.json({ csrfToken: 'token-' + (++handshakes) });
      tokens.push(new Headers(init.headers).get('x-csrf-token')!);
      return Response.json({ success: true });
    }));
    await Promise.all([adminMutation('/admin/one', { method: 'POST' }), adminMutation('/admin/two', { method: 'POST' })]);
    expect(new Set(tokens)).toEqual(new Set(['token-1', 'token-2']));
  });
});
