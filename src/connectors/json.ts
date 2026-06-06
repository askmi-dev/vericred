/**
 * JSON data connector — Sprint 1 default.
 * Loads holder records from a local JSON file, looks up by identifier.
 */
import { readFileSync, existsSync, mkdirSync, writeFileSync } from 'fs';

import type { Connector } from './index.js';

const SAMPLE_DATA = [
  { id: 'student-001', email: 'alice@example.com', firstName: 'Alice', lastName: 'Muster', studentId: 'S-2024-001', program: 'Computer Science' },
  { id: 'student-002', email: 'bob@example.com', firstName: 'Bob', lastName: 'Beispiel', studentId: 'S-2024-002', program: 'Law' },
];

export function loadJsonConnector(path: string): Connector {
  const dir = path.substring(0, path.lastIndexOf('/'));
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  if (!existsSync(path)) {
    writeFileSync(path, JSON.stringify(SAMPLE_DATA, null, 2));
    console.log(`[connector:json] Created sample data at ${path}`);
  }

  const data = JSON.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>[];

  return {
    lookup: (identifier: string) => {
      return data.find(
        (r) => r['id'] === identifier || r['email'] === identifier || r['studentId'] === identifier
      ) ?? null;
    },
    getSchema: () => {
      if (data.length === 0) return ['id', 'email', 'firstName', 'lastName'];
      return Object.keys(data[0]);
    }
  };
}
