import { describe, it, expect, beforeAll } from 'vitest';
import { existsSync, rmSync, mkdirSync, readFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';

describe('Key Management & Rotation', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  const tempDir = './src/admin/__tests__/temp-data-keys';

  beforeAll(async () => {
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });

    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = '3517';
    process.env['ISSUER_URL'] = 'http://localhost:3517';
    serverUrl = 'http://localhost:3517';

    await import('../../server.js');
    await new Promise(resolve => setTimeout(resolve, 500));
  });

  it('generates an initial key on start', async () => {
    const res = await fetch(`${serverUrl}/.well-known/did.json`);
    const did = await res.json() as any;
    expect(did.verificationMethod).toHaveLength(1);
    const initialKid = did.verificationMethod[0].publicKeyJwk.kid;
    expect(initialKid).toBeDefined();
  });

  it('rotates keys and preserves history in DID doc', async () => {
    // 1. Get initial key status
    const status1Res = await fetch(`${serverUrl}/admin/api/keys-status`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    const status1 = await status1Res.json() as any;
    const kid1 = status1.active.kid;

    // 2. Rotate keys
    const rotateRes = await fetch(`${serverUrl}/admin/api/rotate-keys`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    const rotateData = await rotateRes.json() as any;
    expect(rotateData.success).toBe(true);
    const kid2 = rotateData.kid;
    expect(kid2).not.toBe(kid1);

    // 3. Verify DID document has both keys
    const didRes = await fetch(`${serverUrl}/.well-known/did.json`);
    const did = await didRes.json() as any;
    expect(did.verificationMethod).toHaveLength(2);
    const kids = did.verificationMethod.map((m: any) => m.publicKeyJwk.kid);
    expect(kids).toContain(kid1);
    expect(kids).toContain(kid2);

    // 4. Verify keys-status reflects history
    const status2Res = await fetch(`${serverUrl}/admin/api/keys-status`, {
      headers: { 'Authorization': `Bearer ${adminApiKey}` }
    });
    const status2 = await status2Res.json() as any;
    expect(status2.active.kid).toBe(kid2);
    expect(status2.historyCount).toBe(1);
    expect(status2.totalKeys).toBe(2);
  });
});
