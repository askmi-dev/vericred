import { describe, it, expect, vi, afterEach } from 'vitest';
import { loadRestConnector } from '../rest.js';
describe('REST source', () => {
  afterEach(() => vi.unstubAllGlobals());
  it('encodes identifiers, authenticates and bounds requests', async () => {
    const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ id: '001', email: 'a@test.com' }) });
    vi.stubGlobal('fetch', fetch);
    const connector = loadRestConnector({ endpoint: 'https://example.com/{id}', authHeader: 'Bearer test' }, 'secret');
    expect((await connector.lookup('a@test.com'))?.id).toBe('001');
    expect(fetch).toHaveBeenCalledWith('https://example.com/a%40test.com', expect.objectContaining({ headers: { Accept: 'application/json', Authorization: 'Bearer test' }, signal: expect.any(AbortSignal), redirect: 'error' }));
    expect(connector.list).toBeUndefined();
  });
  it('only treats 404 as missing and propagates service/network failures', async () => {
    const fetch = vi.fn().mockResolvedValueOnce({ status: 404 }).mockResolvedValueOnce({ status: 500, ok: false }).mockRejectedValueOnce(new Error('offline'));
    vi.stubGlobal('fetch', fetch);
    const connector = loadRestConnector({ endpoint: 'https://example.com/{id}' }, 'secret');
    expect(await connector.lookup('missing')).toBeNull();
    await expect(connector.lookup('error')).rejects.toThrow('unsuccessful');
    await expect(connector.lookup('error')).rejects.toThrow('offline');
  });
  it('derives schema from an explicit existing holder', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ email: 'a@test.com', department: 'Law' }) }));
    const connector = loadRestConnector({ endpoint: 'https://example.com/{id}', healthCheckIdentifier: 'a@test.com' }, 'secret');
    await connector.healthCheck!();
    expect(await connector.getSchema()).toEqual(['email', 'department']);
    await expect(loadRestConnector({ endpoint: 'https://example.com/{id}' }, 'secret').getSchema()).rejects.toThrow('healthCheckIdentifier');
  });
  it('rejects malformed holder responses and endpoints', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => [] }));
    await expect(loadRestConnector({ endpoint: 'https://example.com/{id}' }, 'secret').lookup('id')).rejects.toThrow('one holder object');
    expect(() => loadRestConnector({ endpoint: 'https://example.com/users' }, 'secret')).toThrow('{id}');
    expect(() => loadRestConnector({ endpoint: 'file:///{id}' }, 'secret')).toThrow('Invalid REST');
  });
});
