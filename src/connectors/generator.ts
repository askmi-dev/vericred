/**
 * Synthetic holder generator.
 * Each server start appends N new holders with a region and derived default password.
 * This is intentional for test mode — each restart = new "session" of synthetic users.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomUUID } from 'crypto';
import { deriveHolderPassword } from '../config/secrets.js';

const REGIONS = [
  'Tirol', 'Salzburg', 'Wien', 'Niederösterreich', 'Oberösterreich', 'Steiermark',
  'Bayern', 'NRW', 'Sachsen', 'Niedersachsen', 'Baden-Württemberg', 'Berlin',
  'Zürich', 'Bern', 'Basel', 'Genf',
];

const FIRST_NAMES = ['Alex', 'Marie', 'Jonas', 'Lena', 'Tobias', 'Sara', 'Felix', 'Mia', 'Noah', 'Emma'];
const LAST_NAMES = ['Müller', 'Schmidt', 'Fischer', 'Weber', 'Mayer', 'Wagner', 'Becker', 'Schulz'];

export interface HolderRecord {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  region: string;
  defaultPassword: string;
  createdAt: string;
  sessionId: string; // groups holders by server start
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

export function generateHolders(
  count: number,
  pseudonymSecret: string,
  sessionId: string,
  dataPath: string
): HolderRecord[] {
  const dir = dataPath.substring(0, dataPath.lastIndexOf('/'));
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const existing: HolderRecord[] = existsSync(dataPath)
    ? JSON.parse(readFileSync(dataPath, 'utf-8'))
    : [];

  const newHolders: HolderRecord[] = Array.from({ length: count }, () => {
    const id = `holder-${randomUUID()}`;
    const firstName = pick(FIRST_NAMES);
    const lastName = pick(LAST_NAMES);
    return {
      id,
      firstName,
      lastName,
      email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}.${id.slice(-6)}@example.com`,
      region: pick(REGIONS),
      defaultPassword: deriveHolderPassword(id, pseudonymSecret),
      createdAt: new Date().toISOString(),
      sessionId,
    };
  });

  writeFileSync(dataPath, JSON.stringify([...existing, ...newHolders], null, 2));
  console.log(`[generator] Spawned ${count} new holders (session: ${sessionId.slice(0, 8)})`);
  return newHolders;
}
