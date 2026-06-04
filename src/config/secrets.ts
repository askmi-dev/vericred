/**
 * Secrets manager — priority order:
 *
 *  1. Environment variables (Railway Secrets / any 12-factor deployment):
 *       ADMIN_API_KEY   -- protects all admin routes
 *       PSEUDO_SECRET   -- HMAC key for pairwise pseudonyms
 *     Both must be set together; partial env config is rejected at startup.
 *
 *  2. Persistent volume file (DATA_DIR/secrets.json, default /data/secrets.json):
 *     Written on first start when env vars are absent.
 *     Mount a Railway Volume at DATA_DIR so this survives redeploys.
 *
 *  3. Local fallback (./keys/secrets.json):
 *     Used in development when neither env vars nor a volume are present.
 *     Gitignored.
 *
 * pseudonymSecret MUST NOT change between redeploys -- pairwise pseudonyms
 * derived from it would silently shift, breaking holder correlation across sessions.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { randomBytes, createHash } from 'crypto';

const DATA_DIR = process.env.DATA_DIR ?? './keys';
const SECRETS_PATH = `${DATA_DIR}/secrets.json`;

interface Secrets {
  adminApiKey: string;
  pseudonymSecret: string;
  createdAt: string;
}

let cached: Secrets | null = null;

export function loadSecrets(): Secrets {
  if (cached) return cached;

  // Priority 1: environment variables (Railway Secrets)
  const envKey = process.env.ADMIN_API_KEY;
  const envPseudo = process.env.PSEUDO_SECRET;

  if (envKey || envPseudo) {
    if (!envKey || !envPseudo) {
      console.error('[secrets] FATAL: ADMIN_API_KEY and PSEUDO_SECRET must both be set, or neither.');
      process.exit(1);
    }
    cached = { adminApiKey: envKey, pseudonymSecret: envPseudo, createdAt: 'from-env' };
    console.log('[secrets] Loaded from environment variables.');
    return cached;
  }

  // Priority 2/3: persistent file (volume or local dev fallback)
  if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

  if (existsSync(SECRETS_PATH)) {
    cached = JSON.parse(readFileSync(SECRETS_PATH, 'utf-8')) as Secrets;
    console.log(`[secrets] Loaded from ${SECRETS_PATH}`);
    return cached;
  }

  // Generate new secrets and persist
  const secrets: Secrets = {
    adminApiKey: randomBytes(24).toString('base64url'),
    pseudonymSecret: randomBytes(32).toString('hex'),
    createdAt: new Date().toISOString(),
  };

  writeFileSync(SECRETS_PATH, JSON.stringify(secrets, null, 2));

  console.log('\n╔════════════════════════════════════════════════════╗');
  console.log('║         VeriCred -- FIRST START SECRETS            ║');
  console.log('╠════════════════════════════════════════════════════╣');
  console.log(`║  Admin API Key : ${secrets.adminApiKey.padEnd(33)} ║`);
  console.log(`║  Saved to      : ${SECRETS_PATH.padEnd(33)} ║`);
  console.log('║  Save the key -- it will not be shown again.       ║');
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
