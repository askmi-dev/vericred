import { deriveHolderPassword } from '../config/secrets.js';
import type { Connector } from './index.js';
import { pageBounds, sqlIdentifier } from './sql.js';

export interface MySQLConfig { connectionString: string; table: string; identifierColumn: string; }

async function getPool(connectionString: string) {
  const mysql = await import('mysql2/promise');
  return mysql.createPool({ uri: connectionString, connectTimeout: 5000, connectionLimit: 5, dateStrings: ['DATE'] });
}

export function loadMySQLConnector(config: MySQLConfig, pseudonymSecret: string): Connector {
  const table = sqlIdentifier(config.table, '`', true);
  const identifierColumn = sqlIdentifier(config.identifierColumn, '`');
  let poolPromise: ReturnType<typeof getPool> | undefined;
  const getConn = () => poolPromise ??= getPool(config.connectionString);
  const decorate = (row: Record<string, unknown>, fallback = '') => {
    const id = String(row['id'] ?? row[config.identifierColumn] ?? fallback);
    return { ...row, id, _lookupIdentifier: String(row[config.identifierColumn] ?? fallback), defaultPassword: deriveHolderPassword(id, pseudonymSecret), _source: 'mysql' };
  };
  const getSchema = async () => {
    const [rows] = await (await getConn()).execute(`DESCRIBE ${table}`, []);
    return (rows as Array<{ Field: string }>).map(row => row.Field);
  };
  return {
    lookup: async identifier => {
      const [rows] = await (await getConn()).execute(`SELECT * FROM ${table} WHERE ${identifierColumn} = ? LIMIT 1`, [identifier]);
      const data = rows as Record<string, unknown>[];
      return data.length ? decorate(data[0], identifier) : null;
    },
    list: async options => {
      const { limit, offset } = pageBounds(options);
      const [rows] = await (await getConn()).execute(`SELECT * FROM ${table} ORDER BY ${identifierColumn} LIMIT ? OFFSET ?`, [limit, offset]);
      return (rows as Record<string, unknown>[]).map(row => decorate(row));
    },
    getSchema,
    healthCheck: async () => {
      const columns = await getSchema();
      if (!columns.includes(config.identifierColumn)) throw new Error('Identifier column does not exist in the source');
    },
    close: async () => { if (poolPromise) await (await poolPromise).end(); },
  };
}
