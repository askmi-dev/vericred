import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import path from 'path';

export interface InteropLogEntry {
  timestamp: string;
  type: 'error' | 'warning' | 'info';
  category: 'metadata' | 'token' | 'proof' | 'issuance';
  message: string;
  details?: any;
}

const DATA_DIR = process.env.DATA_DIR ?? './data';
const LOG_PATH = path.join(DATA_DIR, 'wallet-interop.json');

export function logInterop(entry: Omit<InteropLogEntry, 'timestamp'>) {
  try {
    const fullEntry: InteropLogEntry = {
      timestamp: new Date().toISOString(),
      ...entry
    };

    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

    let logs: InteropLogEntry[] = [];
    if (existsSync(LOG_PATH)) {
      logs = JSON.parse(readFileSync(LOG_PATH, 'utf-8')) as InteropLogEntry[];
    }

    logs.unshift(fullEntry);
    if (logs.length > 100) logs = logs.slice(0, 100); // Keep last 100

    writeFileSync(LOG_PATH, JSON.stringify(logs, null, 2), 'utf-8');
  } catch (err) {
    console.error('[interop-logger] Failed to log:', err);
  }
}

export function getInteropLogs(): InteropLogEntry[] {
  try {
    if (!existsSync(LOG_PATH)) return [];
    return JSON.parse(readFileSync(LOG_PATH, 'utf-8')) as InteropLogEntry[];
  } catch {
    return [];
  }
}
