import { readFileSync, existsSync, writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import type { VeriCredConfig } from './types.js';

// Config lives in DATA_DIR (volume) so it persists across redeploys.
// Falls back to cwd for local development.
const DATA_DIR = process.env.DATA_DIR ?? '.';
const CONFIG_PATH = `${DATA_DIR}/vericred.config.json`;

// ISSUER_URL env var overrides the config file -- set this in Railway dashboard.
const ISSUER_URL = process.env.ISSUER_URL;
const issuerUrlToDidWeb = (issuerUrl: string): string =>
  `did:web:${new URL(issuerUrl).host.replace(/:/g, '%3A')}`;

export const DEFAULT_CONFIG: VeriCredConfig = {
  issuer: {
    name: 'VeriCred Issuer',
    url: ISSUER_URL ?? 'http://localhost:3100',
    did: ISSUER_URL ? issuerUrlToDidWeb(ISSUER_URL) : 'did:web:localhost%3A3100',
  },
  credential: {
    type: 'AgeCredential',
    expiresInDays: 30,
  },
  templateOptions: {
    ageThresholds: [18, 21],
    jurisdiction: 'EU',
  },
  dataSource: {
    type: 'json',
    path: `${DATA_DIR}/holders.json`,
  },
  fieldMappings: {
    dateOfBirth: 'dateOfBirth',
  },
};

export function loadConfig(): VeriCredConfig {
  if (!existsSync(CONFIG_PATH)) {
    mkdirSync(dirname(CONFIG_PATH), { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2));
    console.log(`[config] Created default config at ${CONFIG_PATH}`);
  }
  const cfg = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8')) as VeriCredConfig;

  // Always override issuer.url/did from env var if set -- survives config file edits.
  if (ISSUER_URL) {
    cfg.issuer.url = ISSUER_URL;
    cfg.issuer.did = issuerUrlToDidWeb(ISSUER_URL);
  }

  return cfg;
}
