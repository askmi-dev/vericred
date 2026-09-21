import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { lock } from 'proper-lockfile';
export async function acquireDataLease() {
  const dir = resolve(process.env.DATA_DIR ?? './data');
  mkdirSync(dir, { recursive: true });
  return lock(dir, { lockfilePath: resolve(dir, '.writer.lock'), stale: 30_000, update: 10_000, retries: 0 });
}
