export interface VeriCredConfig {
  issuer: {
    name: string;
    url: string;
    did: string;
  };
  credential: {
    type: string;
    expiresInDays: number;
  };
  dataSource: {
    type: 'json' | 'postgres' | 'mysql' | 'rest' | 'csv';
    path?: string;           // json / csv
    connectionString?: string; // postgres / mysql
    table?: string;          // postgres / mysql (default: users)
    identifierColumn?: string; // postgres / mysql (default: email)
    endpoint?: string;       // rest
    authHeader?: string;     // rest
  };
  fieldMappings: Record<string, string>;
}
