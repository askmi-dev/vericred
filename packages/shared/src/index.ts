export type TenantContext = {
  id: string;
  name: string;
  issuerDid: string;
};

export function createTenantContext(tenantId: string, name: string): TenantContext {
  return {
    id: tenantId,
    name,
    issuerDid: `did:web:${tenantId}.vericred.local`,
  };
}

export type HealthStatus = {
  ok: boolean;
  checkedAt: string;
};

export function createHealthStatus(): HealthStatus {
  return {
    ok: true,
    checkedAt: new Date().toISOString(),
  };
}
