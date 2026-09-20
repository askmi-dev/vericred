import { appendFileSync, mkdirSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
export function audit(action: string, actor: string, resource: string, details: Record<string, unknown> = {}) {
  const dir = process.env.DATA_DIR ?? './data';
  mkdirSync(dir, { recursive: true });
  const fd = openSync(dir + '/audit.jsonl', 'a', 0o600);
  try {
    appendFileSync(fd, JSON.stringify({ id: randomUUID(), timestamp: new Date().toISOString(), action, actor, resource, details }) + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
}
