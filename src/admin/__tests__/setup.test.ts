import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import express from 'express';
import type { Server } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createAdminRouter } from '../router.js';
import { liveConnector } from '../../connectors/index.js';
import { DEFAULT_CONFIG, configPath, saveConfig } from '../../config/loader.js';

describe('Admin source setup', () => {
  let server: Server;
  let url: string;
  const headers = { Authorization: 'Bearer ' + process.env.ADMIN_API_KEY, 'Content-Type': 'application/json' };
  const first = join(process.env.DATA_DIR!, 'first.json');
  const second = join(process.env.DATA_DIR!, 'second.json');
  const source = liveConnector();
  const post = (body: unknown) => fetch(url + '/admin/api/setup', { method: 'POST', headers, body: JSON.stringify(body) });
  beforeAll(async () => {
    const app = express(); app.use(express.json()); app.use(createAdminRouter(source));
    server = app.listen(0, '127.0.0.1');
    await new Promise<void>(resolve => server.once('listening', resolve));
    url = 'http://127.0.0.1:' + (server.address() as { port: number }).port;
  });
  beforeEach(() => {
    vi.unstubAllGlobals();
    writeFileSync(first, JSON.stringify([{ id: 'old', email: 'old@example.com', firstName: 'Old' }]));
    writeFileSync(second, JSON.stringify([{ id: 'new', email: 'new@example.com', firstName: 'New', department: 'Law', password: 'sensitive', apiToken: 'sensitive' }]));
    saveConfig({ ...structuredClone(DEFAULT_CONFIG), dataSource: { type: 'json', path: first } });
  });
  afterAll(async () => {
    vi.unstubAllGlobals();
    await source.close?.();
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  it('activates a validated source immediately for lookup, admin listing and schema', async () => {
    expect((await source.lookup('old'))?.id).toBe('old');
    const response = await post({ name: 'New Issuer', url: 'https://issuer.example.org', dataSource: { type: 'json', path: second } });
    expect(response.status).toBe(200);
    expect((await source.lookup('new'))?.id).toBe('new');
    expect(await source.lookup('old')).toBeNull();
    expect(JSON.parse(readFileSync(configPath(), 'utf8')).issuer.did).toBe('did:web:issuer.example.org');
    const schema = await fetch(url + '/admin/api/source-schema', { headers }).then(r => r.json()) as { columns: string[] };
    expect(schema.columns).toContain('department');
    process.env.PII_ADMIN_MODE = 'true';
    const holders = await fetch(url + '/admin/api/holders', { headers }).then(r => r.json()) as Record<string, unknown>[];
    delete process.env.PII_ADMIN_MODE;
    expect(holders[0].id).toBe('new');
    expect(holders[0]).not.toHaveProperty('password');
    expect(holders[0]).not.toHaveProperty('apiToken');
  });
  it('leaves config and runtime unchanged when the candidate source is unavailable', async () => {
    const before = readFileSync(configPath(), 'utf8');
    const response = await post({ name: 'Invalid Issuer', url: 'https://issuer.example.org', dataSource: { type: 'json', path: second + '.missing' } });
    expect(response.status).toBe(400);
    expect(readFileSync(configPath(), 'utf8')).toBe(before);
    expect((await source.lookup('old'))?.id).toBe('old');
  });
  it('rejects unsafe SQL configuration without changing config', async () => {
    const before = readFileSync(configPath(), 'utf8');
    const response = await post({ name: 'Invalid Issuer', url: 'https://issuer.example.org', dataSource: { type: 'postgres', connectionString: 'postgresql://localhost/test', table: 'users; DROP TABLE users' } });
    expect(response.status).toBe(400);
    expect(readFileSync(configPath(), 'utf8')).toBe(before);
  });
  it('uses CSV connector listing instead of parsing CSV as JSON', async () => {
    const csv = join(process.env.DATA_DIR!, 'holders.csv');
    writeFileSync(csv, 'id,email,region\n0001,csv@example.com,EU');
    expect((await post({ name: 'CSV Issuer', url: 'https://issuer.example.org', dataSource: { type: 'csv', path: csv, identifierColumn: 'email' } })).status).toBe(200);
    const holders = await fetch(url + '/admin/api/holders', { headers }).then(r => r.json()) as Record<string, unknown>[];
    expect(holders[0].id).toBe('0001');
    const stats = await fetch(url + '/admin/api/stats', { headers }).then(r => r.json()) as { regions: Record<string, number> };
    expect(stats.regions.EU).toBe(1);
  });
});
