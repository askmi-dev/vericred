import express from 'express';
import { createTenantContext, type TenantContext } from '@vericred/shared';

const app = express();
const port = Number(process.env.PORT ?? 3100);

app.use(express.json());

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'vericred-api',
    version: '0.1.0',
    timestamp: new Date().toISOString(),
  });
});

app.get('/api/tenant/:tenantId/health', (req, res) => {
  const tenant = createTenantContext(req.params.tenantId, 'demo');
  res.json({
    ok: true,
    tenantId: tenant.id,
    issuerDid: tenant.issuerDid,
    tenantName: tenant.name,
    status: 'healthy',
  });
});

app.get('/api/admin/metrics', (_req, res) => {
  res.json({
    tenants: 1,
    credentialsIssued: 0,
    revokedCredentials: 0,
    activeAlerts: 0,
  });
});

app.listen(port, () => {
  console.log(`VeriCred API listening on http://localhost:${port}`);
});

export type ApiServer = typeof app;
export { app };
