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
  templateOptions?: Record<string, unknown>;
  dataSource: {
    type: 'json' | 'postgres' | 'mysql' | 'rest' | 'csv';
    path?: string;
    connectionString?: string;
    table?: string;
    identifierColumn?: string;
    endpoint?: string;
    authHeader?: string;
  };
  fieldMappings: Record<string, string>;
}
