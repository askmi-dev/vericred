import { it, expect } from 'vitest';
import { spawn } from 'node:child_process';

it('built gateway survives process kills and excludes simultaneous writers', async () => {
  const result = await new Promise<{ code: number | null; output: string }>((resolve, reject) => {
    const child = spawn(process.execPath, ['scripts/verify-persistence.mjs'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (data: Buffer) => { output += data.toString(); });
    child.stderr.on('data', (data: Buffer) => { output += data.toString(); });
    child.once('error', reject);
    child.once('exit', (code) => resolve({ code, output }));
  });
  expect(result.code, result.output).toBe(0);
  expect(result.output).toContain('PASS: simultaneous writers excluded');
}, 120000);
