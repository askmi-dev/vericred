export interface VeriCredConfig {
  issuer: {
    name: string;
    url: string; // base URL, e.g. https://uni.example.com
    did: string; // auto-derived: did:web:uni.example.com
  };
  credential: {
    type: string;         // e.g. "UniversityDegreeCredential"
    expiresInDays: number;
  };
  dataSource: {
    type: 'json' | 'postgres' | 'mysql' | 'rest' | 'csv';
    path?: string;        // for json/csv
    connectionString?: string; // for postgres/mysql
    endpoint?: string;   // for rest
  };
  fieldMappings: Record<string, string>; // VC claim name → source field name
}
