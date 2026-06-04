/**
 * Type stubs for optional connector dependencies.
 * Install the actual package to enable the connector:
 *   npm install pg @types/pg      -- for PostgreSQL
 *   npm install mysql2            -- for MySQL
 */
declare module 'pg' {
  export class Pool {
    constructor(options?: Record<string, unknown>);
    query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
    end(): Promise<void>;
  }
}

declare module 'mysql2/promise' {
  export function createPool(options: { uri: string } | Record<string, unknown>): {
    execute(sql: string, params: unknown[]): Promise<[Record<string, unknown>[], unknown]>;
  };
  export function createConnection(options: Record<string, unknown>): Promise<{
    execute(sql: string, values?: unknown[]): Promise<[Record<string, unknown>[], unknown]>;
    end(): Promise<void>;
  }>;
}
