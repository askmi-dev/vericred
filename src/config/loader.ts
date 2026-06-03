import { readFileSync, existsSync, writeFileSync } from 'fs';
import type { VeriCredConfig } from './types.js';

const CONFIG_PATH = './vericred.config.json';

export const DEFAULT_CONFIG: VeriCredConfig = {
  issuer: {
    name: 'VeriCred Issuer',
    url: 'http://localhost:3100',
    did: 'did:web:localhost%3A3100',
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
    path: './data/holders.json',
  },
  fieldMappings: {
    dateOfBirth: 'dateOfBirth',
  },
};

export function loadConfig(): VeriCredConfig {
  if (!existsSync(CONFIG_PATH)) {
    writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2));
    console.log(`[config] Created default config at ${CONFIG_PATH}`);
  }
  return JSON.parse(readFileSync(CONFIG_PATH, 'utf-8')) as VeriCredConfig;
}
