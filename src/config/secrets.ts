/**
 * Secrets manager — generates and persists:
 *   - adminApiKey: protects all admin routes
 *   - pseudonymSecret: HMAC key for pairwise pseudonyms (must never change per deployment)
 *
 * Both are stored in ./keys/secrets.json (gitignored).
 * On first start they are printed to the console — save them.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomBytes, createHash } from 'crypto';

const KEY_DIR = './keys';
const SECRETS_PATH = `${KEY_DIR}/secrets.json`;

interface Secrets {
  adminApiKey: string;
  pseudonymSecret: string;
  createdAt: string;
}

let cached: Secrets | null = null;

export function loadSecrets(): Secrets {
  if (cached) return cached;
  if (!existsSync(KEY_DIR)) mkdirSync(KEY_DIR, { recursive: true });

  if (existsSync(SECRETS_PATH)) {
    cached = JSON.parse(readFileSync(SECRETS_PATH, 'utf-8')) as Secrets;
    return cached;
  }

  const secrets: Secrets = {
    adminApiKey: randomBytes(24).toString('base64url'),
    pseudonymSecret: randomBytes(32).toString('hex'),
    createdAt: new Date().toISOString(),
  };

  writeFileSync(SECRETS_PATH, JSON.stringify(secrets, null, 2));

  console.log('\n╔════════════════════════════════════════════════════╗');
  console.log('║         VeriCred — FIRST START SECRETS             ║');
  console.log('╠════════════════════════════════════════════════════╣');
  console.log(`║  Admin API Key: ${secrets.adminApiKey.padEnd(34)} ║`);
  console.log('║  Save this — it will not be shown again.           ║');
  console.log('╚════════════════════════════════════════════════════╝\n');

  cached = secrets;
  return cached;
}

export function deriveHolderPassword(holderId: string, pseudonymSecret: string): string {
  return createHash('sha256')
    .update(`${holderId}:${pseudonymSecret}`)
    .digest('base64url')
    .slice(0, 16);
}
