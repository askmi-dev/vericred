import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { once } from 'node:events';

const server = resolve('src/server.ts');
const tsx = resolve('node_modules/tsx/dist/loader.mjs');
const routes: [string, string][] = [
  ['POST', '/initiate'], ['GET', '/client-metadata'], ['GET', '/request/missing'],
  ['POST', '/response/missing'], ['GET', '/session/missing'],
];

// A real child process imports server.ts; no router/server mocks.
async function run(env: Record<string, string>, enabled: boolean, rejected = false) {
  const dir = mkdtempSync(join(tmpdir(), 'vericred-verifier-'));
  const sessions = join(dir, 'oid4vp_sessions.json');
  const sentinel = 'invalid-session-json-for-import-detection';
  writeFileSync(sessions, sentinel);
  const preload = resolve('src/__tests__/listen-port.mjs');
  const child = spawn(process.execPath, ['--import', tsx, '--import', preload, server], {
    cwd: dir,
    env: { ...process.env, PORT: '0', DATA_DIR: dir, NODE_ENV: 'test',
      ENABLE_HOSTED_VERIFIER: '', ENABLE_HOSTED_VERIFIER_CONFIRM: '',
      ...env },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  let output = '';
  child.stdout!.on('data', b => { output += b.toString(); });
  child.stderr!.on('data', b => { output += b.toString(); });
  const exited = once(child, 'exit');
  let startupTimer: ReturnType<typeof setTimeout> | undefined;
  const listening = Promise.race([
    once(child, 'message'),
    exited.then(([code, signal]) => {
      throw new Error(`Server exited before listening (${code ?? signal}): ${output}`);
    }),
    new Promise<never>((_, reject) => {
      startupTimer = setTimeout(() => reject(new Error(`Server did not listen: ${output}`)), 10000);
    }),
  ]);
  // The rejected-startup case intentionally never awaits a listening message.
  void listening.catch(() => {});
  try {
    // Observe the actual ephemeral listening port through the test preload.
    if (rejected) {
      const [code] = await exited;
      expect(code).not.toBe(0);
      expect(output).toContain('ENABLE_HOSTED_VERIFIER_CONFIRM=yes required');
      expect(output).not.toContain('VeriCred running');
    } else {
      // Discover listening socket via a test-only IPC preload.
      const [message] = await listening as [{ port: number }];
      const base = `http://127.0.0.1:${message.port}`;
      for (const [method, path] of routes) {
        const response = await fetch(`${base}/api/oid4vp${path}`, { method, headers: { 'X-Forwarded-Proto': 'https' } });
        if (!enabled) expect(response.status, path).toBe(404);
        else if (path === '/initiate' || path === '/client-metadata') expect(response.status, path).toBe(200);
        else expect(response.status, path).toBe(404);
      }
      expect((await fetch(`${base}/.well-known/openid-credential-issuer`)).status).toBe(200);
      if (!enabled) {
        expect(output).not.toContain('[test] verifier module loaded');
        expect(output).not.toContain('[oid4vp]');
        expect(readFileSync(sessions, 'utf8')).toBe(sentinel);
      } else {
        expect(output).toContain('[test] verifier module loaded');
        expect(output).toContain('[oid4vp] Failed to load/decrypt sessions');
      }
    }
  } finally {
    clearTimeout(startupTimer);
    if (child.exitCode === null) child.kill('SIGTERM');
    await exited;
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('server.ts hosted verifier gate', () => {
  it('defaults off without loading session state', () => run({}, false), 15000);
  it('explicit false disables all five routes', () => run({ ENABLE_HOSTED_VERIFIER: 'false' }, false), 15000);
  it('production defaults off', () => run({ NODE_ENV: 'production' }, false), 15000);
  it('non-true value stays disabled', () => run({ ENABLE_HOSTED_VERIFIER: '1' }, false), 15000);
  it('production explicit acknowledgement permits legacy startup', () => run({ NODE_ENV: 'production', ENABLE_HOSTED_VERIFIER: 'true', ENABLE_HOSTED_VERIFIER_CONFIRM: 'yes' }, true), 15000);
  it('production rejects unconfirmed enablement', () => run({ NODE_ENV: 'production', ENABLE_HOSTED_VERIFIER: 'true' }, false, true), 15000);
  it('explicit test enablement retains legacy router', () => run({ ENABLE_HOSTED_VERIFIER: 'true' }, true), 15000);
});
