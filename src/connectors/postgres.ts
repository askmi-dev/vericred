/**
 * PostgreSQL connector — queries holder data by identifier (email, studentId, or custom field).
 * Install: npm install pg @types/pg
 */
import { deriveHolderPassword } from '../config/secrets.js';

export interface PostgresConfig {
  connectionString: string;
  table: string;                // e.g. "students"
  identifierColumn: string;    // e.g. "email" or "student_id"
}

// Dynamic import so the package is optional — only needed if Postgres connector is active
async function getPool(connectionString: string) {
  const { default: pg } = await import('pg') as { default: { Pool: new (opts: { connectionString: string }) => { query: (sql: string, params: unknown[]) => Promise<{ rows: Record<string, unknown>[] }> } } };
  return new pg.Pool({ connectionString });
}

export function loadPostgresConnector(
  config: PostgresConfig,
  pseudonymSecret: string
): (identifier: string) => Promise<Record<string, unknown> | null> {
  let poolPromise: ReturnType<typeof getPool> | null = null;

  const getConn = () => {
    if (!poolPromise) poolPromise = getPool(config.connectionString);
    return poolPromise;
  };

  return async (identifier: string) => {
    try {
      const pool = await getConn();
      const result = await pool.query(
        `SELECT * FROM ${config.table} WHERE ${config.identifierColumn} = $1 LIMIT 1`,
        [identifier]
      );
      if (result.rows.length === 0) return null;

      const row = result.rows[0];
      const id = String(row['id'] ?? identifier);

      return {
        ...row,
        id,
        defaultPassword: deriveHolderPassword(id, pseudonymSecret),
        _source: 'postgres',
      };
    } catch (err) {
      console.error('[connector:postgres] Query failed:', err);
      return null;
    }
  };
}
