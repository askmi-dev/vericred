import { describe, it, expect } from 'vitest';
import express from 'express';
import { trustedProxies } from '../src/middleware/proxy.js';

describe('Explicit reverse-proxy trust', () => {
  async function peer(trusted: string, forwarded: string) {
    const app = express();
    app.set('trust proxy', trustedProxies(trusted));
    app.get('/', (req, res) => res.json({ ip: req.ip, secure: req.secure }));
    const server = await new Promise<ReturnType<typeof app.listen>>(resolve => {
      const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
    });
    try {
      const port = (server.address() as { port: number }).port;
      return await (await fetch('http://127.0.0.1:' + port, { headers: {
        'X-Forwarded-For': forwarded, 'X-Forwarded-Proto': 'https',
      } })).json();
    } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
  }
  it('ignores spoofed forwarding headers from an untrusted peer', async () => {
    expect(await peer('192.0.2.1/32', '198.51.100.5')).toEqual({ ip: '127.0.0.1', secure: false });
  });
  it('uses the nearest untrusted client and ignores a forged earlier hop', async () => {
    expect(await peer('127.0.0.1/32', '203.0.113.99, 198.51.100.5')).toEqual({ ip: '198.51.100.5', secure: true });
  });
  it('separates legitimate clients behind the trusted proxy', async () => {
    expect((await peer('127.0.0.1', '198.51.100.6')).ip).toBe('198.51.100.6');
    expect((await peer('127.0.0.1', '198.51.100.7')).ip).toBe('198.51.100.7');
  });
  it('rejects trust-all and hop-count configurations', () => {
    for (const value of ['true', '1', '0.0.0.0/0', '::/0', 'loopback', 'bad', '127.0.0.1/33']) {
      expect(() => trustedProxies(value)).toThrow();
    }
    expect(trustedProxies('')).toBe(false);
  });
});
