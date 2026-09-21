import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { VeriCredConfig } from './types.js';
import { validateConfig } from './validate.js';
import { atomicWrite } from '../storage/atomic.js';

export const issuerUrlToDidWeb = (issuerUrl: string): string => {
  const url = new URL(issuerUrl);
  return 'did:web:' + url.host.replace(/:/g, '%3A') + url.pathname.split('/').filter(Boolean).map(part => ':' + encodeURIComponent(decodeURIComponent(part))).join('');
};
export function configPath(): string { return join(process.env.DATA_DIR ?? '.', 'vericred.config.json'); }
export const DEFAULT_CONFIG: VeriCredConfig = {
  issuer: { name: 'VeriCred Issuer', url: 'http://localhost:3100', did: 'did:web:localhost%3A3100' },
  credential: { type: 'AgeCredential', expiresInDays: 30 },
  templateOptions: { ageThresholds: [18, 21], jurisdiction: 'EU' },
  dataSource: { type: 'json', path: './holders.json' },
  fieldMappings: { dateOfBirth: 'dateOfBirth' },
};
export class ConfigConflictError extends Error {
  constructor() { super('Configuration changed. Reload and retry.'); this.name = 'ConfigConflictError'; }
}
/** Synchronous compare-and-swap; the DATA_DIR lease supplies the single-writer boundary. */
export function saveConfig(config: VeriCredConfig, expectedRevision = config.revision): VeriCredConfig {
  const currentRevision = existsSync(configPath())
    ? (JSON.parse(readFileSync(configPath(), 'utf8')).revision ?? 0) as number : 0;
  if (expectedRevision !== undefined && expectedRevision !== currentRevision) throw new ConfigConflictError();
  const saved = validateConfig({ ...config, revision: currentRevision + 1 });
  atomicWrite(configPath(), JSON.stringify(saved, null, 2));
  return saved;
}
/** Also detects out-of-band edits that did not increment the persisted revision. */
export function assertConfigUnchanged(snapshot: VeriCredConfig): void {
  if (JSON.stringify(loadConfig()) !== JSON.stringify(snapshot)) throw new ConfigConflictError();
}
export function loadConfig(): VeriCredConfig {
  if (!existsSync(configPath())) {
    const defaults = structuredClone(DEFAULT_CONFIG);
    defaults.dataSource.path = join(process.env.DATA_DIR ?? '.', 'holders.json');
    if (process.env.ISSUER_URL) { defaults.issuer.url = process.env.ISSUER_URL; defaults.issuer.did = issuerUrlToDidWeb(process.env.ISSUER_URL); }
    saveConfig(defaults);
  }
  const config = JSON.parse(readFileSync(configPath(), 'utf8')) as VeriCredConfig;
  if (process.env.ISSUER_URL) {
    config.issuer.url = process.env.ISSUER_URL;
    config.issuer.did = issuerUrlToDidWeb(process.env.ISSUER_URL);
  }
  return validateConfig({ ...config, revision: config.revision ?? 0 });
}
