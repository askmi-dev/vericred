/**
 * Connector factory — reads config.dataSource.type and returns the right lookup function.
 */
import type { VeriCredConfig } from '../config/types.js';
import { loadSecrets } from '../config/secrets.js';
import { loadJsonConnector } from './json.js';
import { loadPostgresConnector } from './postgres.js';
import { loadMySQLConnector } from './mysql.js';
import { loadRestConnector } from './rest.js';
import { loadCSVConnector } from './csv.js';
import { loadManualConnector } from './manual.js';
import { sanitizeSourceRef } from '../provenance/types.js';

export type Lookup = (id: string) => Promise<Record<string, unknown> | null> | Record<string, unknown> | null;

export interface Connector {
  lookup: Lookup;
  getSchema: () => Promise<string[]> | string[];
}

/**
 * Provenance context for Art. 6a audit records (#26): what kind of
 * source the attribute data came from and an opaque reference to it.
 * `verificationMode` distinguishes an authoritative system-of-record
 * read (SQL/REST/CSV/JSON) from an admin-attested entry (manual).
 */
export type VerificationMode = 'authoritative-source' | 'admin-attested';

export interface ProvenanceContext {
  connectorType: 'json' | 'postgres' | 'mysql' | 'rest' | 'csv' | 'manual';
  sourceRef: string;
  verificationMode: VerificationMode;
}

export function buildProvenanceContext(config: VeriCredConfig): ProvenanceContext {
  const ds = config.dataSource;
  switch (ds.type) {
    case 'postgres':
    case 'mysql':
      return { connectorType: ds.type, sourceRef: `table:${ds.table ?? 'users'}`, verificationMode: 'authoritative-source' };
    case 'rest':
      // #36 review: endpoints can embed credentials, tokens or identifying
      // query parameters — sanitize before anything is persisted.
      return { connectorType: 'rest', sourceRef: sanitizeSourceRef(ds.endpoint ?? 'rest'), verificationMode: 'authoritative-source' };
    case 'json':
    case 'csv':
      return { connectorType: ds.type, sourceRef: sanitizeSourceRef(ds.path ?? `data/holders.${ds.type}`), verificationMode: 'authoritative-source' };
    case 'manual':
      return { connectorType: 'manual', sourceRef: sanitizeSourceRef(ds.path ?? 'data/manual.json'), verificationMode: 'admin-attested' };
    default:
      throw new Error(`[connector] Unknown dataSource.type: ${(ds as { type: string }).type}`);
  }
}

export function buildConnector(config: VeriCredConfig): Connector {
  const { pseudonymSecret } = loadSecrets();
  const ds = config.dataSource;

  switch (ds.type) {
    case 'json':
      return loadJsonConnector(ds.path ?? './data/holders.json');

    case 'postgres':
      if (!ds.connectionString) throw new Error('[connector] Postgres requires connectionString in config');
      return loadPostgresConnector(
        { connectionString: ds.connectionString, table: ds.table ?? 'users', identifierColumn: ds.identifierColumn ?? 'email' },
        pseudonymSecret
      );

    case 'mysql':
      if (!ds.connectionString) throw new Error('[connector] MySQL requires connectionString in config');
      return loadMySQLConnector(
        { connectionString: ds.connectionString, table: ds.table ?? 'users', identifierColumn: ds.identifierColumn ?? 'email' },
        pseudonymSecret
      );

    case 'rest':
      if (!ds.endpoint) throw new Error('[connector] REST requires endpoint in config');
      return loadRestConnector({ endpoint: ds.endpoint, authHeader: ds.authHeader }, pseudonymSecret);

    case 'csv':
      return loadCSVConnector(
        { path: ds.path ?? './data/holders.csv', identifierColumn: ds.identifierColumn ?? 'email' },
        pseudonymSecret
      );

    case 'manual':
      return loadManualConnector({ path: ds.path }, pseudonymSecret);

    default:
      throw new Error(`[connector] Unknown dataSource.type: ${(ds as { type: string }).type}`);
  }
}
