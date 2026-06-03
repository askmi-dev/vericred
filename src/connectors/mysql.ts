/**
 * MySQL connector — same interface as Postgres.
 * Install: npm install mysql2
 */
import { deriveHolderPassword } from '../config/secrets.js';

export interface MySQLConfig {
  connectionString: string;
  table: string;
  identifierColumn: string;
}

async function getConnection(connectionString: string) {
  const mysql = await import('mysql2/promise') as { createPool: (opts: { uri: string }) => { execute: (sql: string, params: unknown[]) => Promise<[Record<string, unknown>[], unknown]> } };
  return mysql.createPool({ uri: connectionString });
}

export function loadMySQLConnector(
  config: MySQLConfig,
  pseudonymSecret: string
): (identifier: string) => Promise<Record<string, unknown> | null> {
  let poolPromise: ReturnType<typeof getConnection> | null = null;

  const getConn = () => {
    if (!poolPromise) poolPromise = getConnection(config.connectionString);
    return poolPromise;
  };

  return async (identifier: string) => {
    try {
      const pool = await getConn();
      const [rows] = await pool.execute(
        `SELECT * FROM ${config.table} WHERE ${config.identifierColumn} = ? LIMIT 1`,
        [identifier]
      );
      const data = rows as Record<string, unknown>[];
      if (data.length === 0) return null;

      const row = data[0];
      const id = String(row['id'] ?? identifier);
      return { ...row, id, defaultPassword: deriveHolderPassword(id, pseudonymSecret), _source: 'mysql' };
    } catch (err) {
      console.error('[connector:mysql] Query failed:', err);
      return null;
    }
  };
}
