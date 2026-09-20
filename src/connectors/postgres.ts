import { deriveHolderPassword } from '../config/secrets.js';
import type { Connector } from './index.js';
import { pageBounds, sqlIdentifier } from './sql.js';

export interface PostgresConfig { connectionString: string; table: string; identifierColumn: string; }

async function getPool(connectionString: string) {
  const { default: pg } = await import('pg');
  // DATE is a calendar date, not a timestamp. Preserve the server's YYYY-MM-DD text.
  const getTypeParser = ((oid: number, format?: 'text' | 'binary') =>
    oid === 1082 && format !== 'binary' ? (value: string) => value : pg.types.getTypeParser(oid, format as 'text')
  ) as typeof pg.types.getTypeParser;
  const pool = new pg.Pool({ connectionString, connectionTimeoutMillis: 5000, query_timeout: 10000, max: 5, types: { getTypeParser } });
  // The pool removes failed idle clients; handle its event so an outage cannot terminate the issuer.
  pool.on('error', () => console.error('[connector:postgres] Idle database connection failed'));
  return pool;
}

export function loadPostgresConnector(config: PostgresConfig, pseudonymSecret: string): Connector {
  const table = sqlIdentifier(config.table, '"', true);
  const identifierColumn = sqlIdentifier(config.identifierColumn, '"');
  let poolPromise: ReturnType<typeof getPool> | undefined;
  const getConn = () => poolPromise ??= getPool(config.connectionString);
  const decorate = (row: Record<string, unknown>, fallback = '') => {
    const id = String(row['id'] ?? row[config.identifierColumn] ?? fallback);
    return { ...row, id, _lookupIdentifier: String(row[config.identifierColumn] ?? fallback), defaultPassword: deriveHolderPassword(id, pseudonymSecret), _source: 'postgres' };
  };
  const getSchema = async () => {
    const result = await (await getConn()).query(`SELECT * FROM ${table} LIMIT 0`);
    return result.fields.map(field => field.name);
  };
  return {
    lookup: async identifier => {
      const result = await (await getConn()).query(`SELECT * FROM ${table} WHERE ${identifierColumn} = $1 LIMIT 1`, [identifier]);
      return result.rows.length ? decorate(result.rows[0], identifier) : null;
    },
    list: async options => {
      const { limit, offset } = pageBounds(options);
      const result = await (await getConn()).query(`SELECT * FROM ${table} ORDER BY ${identifierColumn} LIMIT $1 OFFSET $2`, [limit, offset]);
      return result.rows.map(row => decorate(row));
    },
    getSchema,
    healthCheck: async () => {
      const columns = await getSchema();
      if (!columns.includes(config.identifierColumn)) throw new Error('Identifier column does not exist in the source');
    },
    close: async () => { if (poolPromise) await (await poolPromise).end(); },
  };
}
