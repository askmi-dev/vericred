/**
 * Runtime log — tracks server restarts and daily stats.
 */
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { randomUUID } from 'crypto';

const DATA_DIR = process.env.DATA_DIR ?? '.';
const RUNTIME_PATH = `${DATA_DIR}/runtime.json`;

export interface RuntimeEntry {
  sessionId: string;
  startedAt: string;
  holdersSpawned: number;
}

export function logStartup(holdersSpawned: number): string {
  const sessionId = randomUUID();
  const entries: RuntimeEntry[] = existsSync(RUNTIME_PATH)
    ? JSON.parse(readFileSync(RUNTIME_PATH, 'utf-8'))
    : [];

  entries.push({ sessionId, startedAt: new Date().toISOString(), holdersSpawned });
  writeFileSync(RUNTIME_PATH, JSON.stringify(entries, null, 2));
  return sessionId;
}

export function getRuntimeStats() {
  const entries: RuntimeEntry[] = existsSync(RUNTIME_PATH)
    ? JSON.parse(readFileSync(RUNTIME_PATH, 'utf-8'))
    : [];

  const today = new Date().toISOString().slice(0, 10);
  const todayEntries = entries.filter(e => e.startedAt.startsWith(today));

  return {
    totalRestarts: entries.length,
    todayRestarts: todayEntries.length,
    todayHoldersSpawned: todayEntries.reduce((sum, e) => sum + e.holdersSpawned, 0),
    sessions: entries.slice(-20).reverse(), // last 20
  };
}

let _processStart: Date | null = null;

export function markProcessStart(): void {
  _processStart = new Date();
}

export function getUptime(): string {
  if (!_processStart) return '—';
  const ms = Date.now() - _processStart.getTime();
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}
