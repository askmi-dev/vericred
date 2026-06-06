import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, rmSync, mkdirSync, writeFileSync, readFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';

describe('Admin Setup & Introspection', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;

  beforeAll(async () => {
    const tempDir = './src/admin/__tests__/temp-data-setup';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });

    // Start with a "fresh" config
    const freshConfig = {
      issuer: { name: 'VeriCred Issuer', url: 'http://localhost:3100', did: '' },
      credential: { type: 'AgeCredential', expiresInDays: 30 },
      dataSource: { type: 'json', path: `${tempDir}/holders.json` },
      fieldMappings: {}
    };
    writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify(freshConfig, null, 2));
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([{ id: 'h1', email: 'h1@ex.com', firstName: 'H1' }], null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = '3516';
    process.env['ISSUER_URL'] = 'http://localhost:3516';
    serverUrl = 'http://localhost:3516';

    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('detects unconfigured status', async () => {
    const res = await fetch(`${serverUrl}/admin/api/setup-status`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    const data = await res.json() as any;
    expect(data.isUnconfigured).toBe(true);
  });

  it('performs setup and updates config', async () => {
    const setupRes = await fetch(`${serverUrl}/admin/api/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminApiKey}` },
      body: JSON.stringify({
        name: 'University of Graz',
        url: 'https://vericred.uni-graz.at',
        dataSource: { type: 'json', path: './data/holders.json' }
      })
    });
    const setupData = await setupRes.json() as any;
    if (setupRes.status !== 200) {
      console.error('Setup failed:', setupRes.status, setupData);
    }
    expect(setupRes.status).toBe(200);
    expect(setupData.success).toBe(true);

    const statusRes = await fetch(`${serverUrl}/admin/api/setup-status`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    const statusData = await statusRes.json() as any;
    expect(statusData.isUnconfigured).toBe(false);

    // Verify file persistence
    const config = JSON.parse(readFileSync(`${process.env['DATA_DIR']}/vericred.config.json`, 'utf-8'));
    expect(config.issuer.name).toBe('University of Graz');
    expect(config.issuer.did).toBe('did:web:vericred.uni-graz.at');
  });

  it('introspects source schema', async () => {
    const res = await fetch(`${serverUrl}/admin/api/source-schema`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    const data = await res.json() as any;
    expect(data.columns).toContain('email');
    expect(data.columns).toContain('firstName');
    expect(data.columns).toContain('id');
  });
});
