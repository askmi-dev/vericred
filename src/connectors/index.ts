/**
 * Connector factory — reads config.dataSource.type and returns the right lookup function.
 */
import type { VeriCredConfig } from '../config/types.js';
import { loadSecrets } from '../config/secrets.js';
import { loadJsonConnector } from './json.js';
import { loadPostgresConnector } from './postgres.js';
import { loadMySQLConnector } from './mysql.js';
import { loadRestConnector } from './rest.js';

export type SyncLookup = (id: string) => Record<string, unknown> | null;
export type AsyncLookup = (id: string) => Promise<Record<string, unknown> | null>;
export type Lookup = SyncLookup | AsyncLookup;

export function buildConnector(config: VeriCredConfig): Lookup {
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

    default:
      throw new Error(`[connector] Unknown dataSource.type: ${(ds as { type: string }).type}`);
  }
}
