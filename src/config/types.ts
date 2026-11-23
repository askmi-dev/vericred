export interface VeriCredConfig {
  issuer: {
    name: string;
    url: string;
    did: string;
    /**
     * Optional path to a PEM file with the issuer's X.509 certificate chain:
     * issuer (leaf) certificate first, then intermediates, without the root.
     * When set, SD-JWT VCs and Status List Tokens carry it as `x5c` (HAIP 1.0)
     * and `iss` becomes `url`, which must match the leaf's subjectAltName.
     * The leaf must certify the current issuer key.
     */
    certificateChain?: string;
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
    /**
     * Max credentials per OID4VCI batch request (advertised as
     * batch_credential_issuance.batch_size). Wallets use one copy per
     * verifier so presentations can't be linked. Default: 10.
     */
    batchSize?: number;
  };
  templateOptions?: Record<string, unknown>;
  dataSource: {
    type: 'json' | 'postgres' | 'mysql' | 'rest' | 'csv' | 'manual';
    path?: string;
    connectionString?: string;
    table?: string;
    identifierColumn?: string;
    endpoint?: string;
    authHeader?: string;
  };
  fieldMappings: Record<string, string>;
}
