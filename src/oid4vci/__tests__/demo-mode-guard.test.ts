/**
 * #32: DEMO_MODE guardrails.
 *
 * DEMO_MODE disables holder proof-of-possession (unbound credentials).
 * In a production deployment (NODE_ENV=production) that combination
 * must fail closed:
 *  - at startup: the server refuses to boot (process.exit(1))
 *  - at issuance: /credentials refuses the anonymous fallback
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'fs';
import { loadSecrets } from '../../config/secrets.js';

describe('#32: DEMO_MODE + NODE_ENV=production guardrails', () => {
  let serverUrl: string;
  const adminApiKey = loadSecrets().adminApiKey;
  const exitSpyCalls: number[] = [];

  beforeAll(async () => {
    // Isolated environment, mirroring dynamic-issuance.test.ts
    const tempDir = './src/oid4vci/__tests__/temp-data-guard';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(`${tempDir}/holders.json`, JSON.stringify([
      { id: 'holder-guard-01', email: 'guard@example.com', dateOfBirth: '1990-01-01' }
    ], null, 2));
    writeFileSync(`${tempDir}/vericred.config.json`, JSON.stringify({
      issuer: { name: 'Guard Test', url: 'http://localhost:3519', did: 'did:web:localhost%3A3519' },
      credential: { type: 'AgeCredential', expiresInDays: 30 },
      templateOptions: { ageThresholds: [18, 21], jurisdiction: 'EU' },
      dataSource: { type: 'json', path: `${tempDir}/holders.json` },
      fieldMappings: { dateOfBirth: 'dateOfBirth' }
    }, null, 2));

    process.env['DATA_DIR'] = tempDir;
    process.env['PORT'] = '3519';
    process.env['ISSUER_URL'] = 'http://localhost:3519';
    // The misconfiguration under test:
    process.env['DEMO_MODE'] = 'true';
    process.env['NODE_ENV'] = 'production';

    // Intercept process.exit so a fatal config aborts the import chain
    // instead of killing the test runner.
    const origExit = process.exit;
    (process as unknown as { exit: (code?: number) => never }).exit = (code?: number) => {
      exitSpyCalls.push(code ?? 0);
      throw new Error('FATAL_EXIT_' + (code ?? 0));
    };
    try {
      await import('../../server.js');
    } catch (e) {
      // Expected: server must refuse to start under this combination.
      if (!(e instanceof Error) || !e.message.startsWith('FATAL_EXIT_')) throw e;
    } finally {
      (process as unknown as { exit: (code?: number) => never }).exit = origExit;
    }
    // The server must NOT be listening under this configuration.
    serverUrl = 'http://localhost:3519';
  }, 30000);

  afterAll(() => {
    delete process.env['DEMO_MODE'];
    delete process.env['NODE_ENV'];
    const tempDir = './src/oid4vci/__tests__/temp-data-guard';
    if (existsSync(tempDir)) rmSync(tempDir, { recursive: true, force: true });
  });

  it('refuses to start when DEMO_MODE=true and NODE_ENV=production', () => {
    expect(exitSpyCalls.length).toBe(1);
    expect(exitSpyCalls[0]).toBe(1);
  });

  it('leaves no server listening on the configured port', async () => {
    // If the guard failed and the server booted anyway, this fetch would
    // succeed (or return a real HTTP error) instead of a connection refusal.
    await expect(
      fetch(`${serverUrl}/.well-known/openid-credential-issuer`)
    ).rejects.toThrow();
  }, 10000);
});
