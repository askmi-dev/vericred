export interface VeriCredConfig {
  issuer: {
    name: string;
    url: string;
    did: string;
  };
  credential: {
    type: string;
    expiresInDays: number;
    /**
     * SD-JWT-VC format identifier used in metadata and credential response.
     * "dc+sd-jwt" -- current (draft-ietf-oauth-sd-jwt-vc-04+)
     * "vc+sd-jwt" -- older drafts; some wallets (Sphereon, older walt.id) still expect this
     * Default: "dc+sd-jwt"
     */
    format?: 'dc+sd-jwt' | 'vc+sd-jwt';
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
