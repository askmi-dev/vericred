import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomUUID } from 'crypto';
import { deriveHolderPassword } from '../config/secrets.js';

const REGION_TIMEZONE: Record<string, string> = {
  'Tirol': 'Europe/Vienna',
  'Salzburg': 'Europe/Vienna',
  'Wien': 'Europe/Vienna',
  'Niederösterreich': 'Europe/Vienna',
  'Oberösterreich': 'Europe/Vienna',
  'Steiermark': 'Europe/Vienna',
  'Bayern': 'Europe/Berlin',
  'NRW': 'Europe/Berlin',
  'Sachsen': 'Europe/Berlin',
  'Niedersachsen': 'Europe/Berlin',
  'Baden-Württemberg': 'Europe/Berlin',
  'Berlin': 'Europe/Berlin',
  'Zürich': 'Europe/Zurich',
  'Bern': 'Europe/Zurich',
  'Basel': 'Europe/Zurich',
  'Genf': 'Europe/Zurich',
};

const REGIONS = Object.keys(REGION_TIMEZONE);
const FIRST_NAMES = ['Alex', 'Marie', 'Jonas', 'Lena', 'Tobias', 'Sara', 'Felix', 'Mia', 'Noah', 'Emma'];
const LAST_NAMES = ['Müller', 'Schmidt', 'Fischer', 'Weber', 'Mayer', 'Wagner', 'Becker', 'Schulz'];

export const SUPPORTED_TIMEZONES = ['Europe/Vienna', 'Europe/Berlin', 'Europe/Zurich'];

export interface HolderRecord {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
  region: string;
  timezone: string;
  defaultPassword: string;
  customPassword?: string;
  createdAt: string; // always stored as UTC ISO string
  sessionId: string;
}

function pick<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }

export function generateHolders(count: number, pseudonymSecret: string, sessionId: string, dataPath: string): HolderRecord[] {
  const dir = dataPath.substring(0, dataPath.lastIndexOf('/'));
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  const existing: HolderRecord[] = existsSync(dataPath) ? JSON.parse(readFileSync(dataPath, 'utf-8')) : [];

  const newHolders: HolderRecord[] = Array.from({ length: count }, () => {
    const id = `holder-${randomUUID()}`;
    const firstName = pick(FIRST_NAMES);
    const lastName = pick(LAST_NAMES);
    const region = pick(REGIONS);
    return {
      id,
      firstName,
      lastName,
      email: `${firstName.toLowerCase()}.${lastName.toLowerCase()}.${id.slice(-6)}@example.com`,
      region,
      timezone: REGION_TIMEZONE[region] ?? 'Europe/Vienna',
      defaultPassword: deriveHolderPassword(id, pseudonymSecret),
      createdAt: new Date().toISOString(),
      sessionId,
    };
  });

  writeFileSync(dataPath, JSON.stringify([...existing, ...newHolders], null, 2));
  console.log(`[generator] Spawned ${count} new holders (session: ${sessionId.slice(0, 8)})`);
  return newHolders;
}

export function setHolderPassword(dataPath: string, holderId: string, newPassword: string): boolean {
  if (!existsSync(dataPath)) return false;
  const holders: HolderRecord[] = JSON.parse(readFileSync(dataPath, 'utf-8'));
  const holder = holders.find(h => h.id === holderId);
  if (!holder) return false;
  holder.customPassword = newPassword;
  writeFileSync(dataPath, JSON.stringify(holders, null, 2));
  return true;
}

export function setHolderTimezone(dataPath: string, holderId: string, timezone: string): boolean {
  if (!SUPPORTED_TIMEZONES.includes(timezone)) return false;
  if (!existsSync(dataPath)) return false;
  const holders: HolderRecord[] = JSON.parse(readFileSync(dataPath, 'utf-8'));
  const holder = holders.find(h => h.id === holderId);
  if (!holder) return false;
  holder.timezone = timezone;
  writeFileSync(dataPath, JSON.stringify(holders, null, 2));
  return true;
}

/** Format a UTC ISO date string in a given IANA timezone */
export function formatInTimezone(isoString: string, timezone: string): string {
  return new Intl.DateTimeFormat('de-AT', {
    timeZone: timezone,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  }).format(new Date(isoString));
}
