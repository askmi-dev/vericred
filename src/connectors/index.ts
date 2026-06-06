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

export type Lookup = (id: string) => Promise<Record<string, unknown> | null> | Record<string, unknown> | null;

export interface Connector {
  lookup: Lookup;
  getSchema: () => Promise<string[]> | string[];
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

