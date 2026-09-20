import { audit } from '../storage/audit.js';
import { getWalletProfile } from '../wallet/profile.js';
import { validateConfig } from '../config/validate.js';
import { buildConnector, ListingUnavailableError } from '../connectors/index.js';
import { pageBounds } from '../connectors/sql.js';
import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { requireAdmin } from '../middleware/auth.js';
import { getRuntimeStats } from './runtime.js';
import { getReadiness } from './readiness.js';
import { getIssuedCredentials } from '../revocation/statuslist.js';
import { loadSecrets } from '../config/secrets.js';
import { createSession, destroySession, createCsrfToken, requireCsrf, cookieFlags, getSessionId } from '../middleware/auth.js';
import { setHolderPassword } from '../connectors/generator.js';
import { listTemplates, getTemplate } from '../credentials/registry.js';
import { maskHolderRecord } from './masking.js';
import { assertConfigUnchanged, ConfigConflictError, loadConfig, saveConfig, issuerUrlToDidWeb } from '../config/loader.js';
import { resolveTemplateConfig, selectTemplate } from '../config/template.js';
import type { Connector } from '../connectors/index.js';
import { getIssuerKeyPair, rotateIssuerKeyPair, getAllPublicKeys } from '../keys/manager.js';
import { calculateJwkThumbprint, exportJWK } from 'jose';
import { getInteropLogs } from '../oid4vci/interop-logger.js';
// Register templates so they appear in listTemplates()
import '../credentials/templates/age.js';
import '../credentials/templates/employee.js';
import '../credentials/templates/membership.js';

function groupByRegion(holders: Record<string, unknown>[]) {
  return holders.reduce<Record<string, number>>((groups, holder) => {
    const region = String(holder.region ?? 'Unknown');
    groups[region] = (groups[region] ?? 0) + 1;
    return groups;
  }, {});
}
const activeCredential = (credential: { revoked: boolean; expiresAt?: string }) =>
  !credential.revoked && Boolean(credential.expiresAt) && Date.parse(credential.expiresAt!) > Date.now();

export function createAdminRouter(connector: Connector): Router {
  const router = createRouter();

  router.get('/admin/api/readiness', requireAdmin, async (_req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    try { res.json(await getReadiness()); }
    catch { res.status(503).json({ error: 'readiness_unavailable', detail: 'Readiness could not be determined from the current configuration.' }); }
  });

  router.get('/admin/api/setup-status', requireAdmin, (_req, res) => {
    const config = loadConfig();
    // Default name is 'VeriCred Issuer'. If it's still that, we're likely unconfigured.
    const isUnconfigured = config.issuer.name === 'VeriCred Issuer';
    res.json({ isUnconfigured, revision: config.revision });
  });

  router.post('/admin/api/setup', requireAdmin, requireCsrf, async (req, res) => {
    let candidate: Connector | undefined;
    try {
      const { name, url, dataSource, revision } = req.body ?? {};
      const previous = loadConfig();
      if (revision !== undefined && revision !== previous.revision) throw new ConfigConflictError();
      const config = validateConfig({
        ...previous,
        issuer: { name, url, did: typeof url === 'string' ? issuerUrlToDidWeb(url) : '' },
        ...(dataSource ? { dataSource } : {}),
      });
      candidate = buildConnector(config);
      if (candidate.healthCheck) await candidate.healthCheck(); else await candidate.getSchema();
      assertConfigUnchanged(previous);
      if ((config.issuer.url !== previous.issuer.url || config.issuer.did !== previous.issuer.did) && getIssuedCredentials().length) {
        res.status(409).json({ error: 'issuer_migration_required', detail: 'Issued credentials bind this issuer authority. Use a separate issuer deployment or an explicit migration.' }); return;
      }
      audit('config.setup', res.locals.actor ?? 'admin', 'issuer', { dataSourceType: config.dataSource.type });
      const saved = saveConfig(config, previous.revision ?? 0);
      if (connector.activate) { connector.activate(saved, candidate); candidate = undefined; }
      res.json({ success: true, revision: saved.revision, message: 'Configuration validated and activated successfully', issuerUrlOverride: process.env.ISSUER_URL ?? null });
    } catch (error) {
      if (error instanceof ConfigConflictError) { res.status(409).json({ error: 'configuration_changed', detail: error.message }); return; }
      res.status(400).json({ error: 'Configuration was not saved. Check issuer settings, source configuration and connectivity; REST requires healthCheckIdentifier.' });
    } finally {
      try { await candidate?.close?.(); } catch { console.error('[setup] Failed to close source probe'); }
    }
  });

  router.get('/admin/api/keys-status', requireAdmin, async (_req, res) => {
    try {
      const { kid, publicKey } = await getIssuerKeyPair();
      const allKeys = await getAllPublicKeys();
      const thumbprint = await calculateJwkThumbprint(await exportJWK(publicKey), 'sha256');

      res.json({
        active: { kid, thumbprint },
        totalKeys: allKeys.length,
        historyCount: allKeys.length - 1
      });
    } catch (err) {
      res.status(500).json({ error: 'failed to fetch key status' });
    }
  });

  router.get('/admin/api/interop-logs', requireAdmin, (_req, res) => {
    res.json(getInteropLogs());
  });

  router.post('/admin/api/rotate-keys', requireAdmin, requireCsrf, async (_req, res) => {
    try {
      if (getWalletProfile() === 'eudi-android') {
        res.status(409).json({ error: 'certificate_rotation_required', detail: 'Coordinate replacement of issuer signing keys, certificates, and trust registration before rotating an EUDI issuer.' }); return;
      }
      const newKey = await rotateIssuerKeyPair(res.locals.actor);
      res.json({ success: true, message: 'Keys rotated successfully!', kid: newKey.kid });
    } catch (err) {
      res.status(500).json({ error: 'failed to rotate keys' });
    }
  });

  router.get('/admin/api/source-schema', requireAdmin, async (_req, res) => {
    try {
      const columns = await connector.getSchema();
      res.json({ columns });
    } catch (err) {
      res.status(503).json({ error: 'Source schema unavailable. Check source connectivity; REST requires healthCheckIdentifier.' });
    }
  });

  router.get('/admin/login', (_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send('<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><title>VeriCred Admin</title><link rel="icon" type="image/svg+xml" href="/favicon.svg">'
      + '<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;width:360px}h1{font-size:1.4rem;margin-bottom:.25rem;color:#f1f5f9}p{font-size:.85rem;color:#94a3b8;margin-bottom:1.5rem}input{width:100%;padding:.6rem .8rem;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0;font-size:.9rem;margin-bottom:1rem}button{width:100%;padding:.7rem;background:#6366f1;border:none;border-radius:6px;color:white;font-size:.95rem;cursor:pointer}button:hover{background:#4f46e5}</style>'
      + '</head><body><div class="card"><h1>VeriCred</h1><p>Admin-Zugang</p>'
      + '<form method="POST" action="/admin/login"><input type="password" name="apiKey" placeholder="Admin API Key" autofocus required /><button type="submit">Einloggen</button></form>'
      + '</div></body></html>');
  });

  router.post('/admin/login', (req, res) => {
    const { apiKey } = req.body as { apiKey: string };
    if (apiKey === loadSecrets().adminApiKey) {
      const sessionToken = createSession();
      res.setHeader('Set-Cookie', 'admin_session=' + sessionToken + cookieFlags());
      res.redirect('/console/dashboard');
      return;
    }
    res.redirect('/admin/login?err=1');
  });

  router.get('/admin/logout', (req, res) => {
    const rawCookie = req.headers.cookie ?? '';
    const part = rawCookie.split(';').find(c => c.trim().startsWith('admin_session='));
    if (part) destroySession(part.split('=').slice(1).join('=').trim());
    res.setHeader('Set-Cookie', 'admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict' + (process.env['NODE_ENV'] === 'production' ? '; Secure' : ''));
    res.redirect('/admin/login');
  });

  router.post('/admin/holder/password', requireAdmin, requireCsrf, (req, res) => {
    const { holderId, password } = req.body as { holderId?: string; password?: string };
    if (typeof holderId !== 'string' || typeof password !== 'string') { res.status(400).json({ error: 'holderId and password required' }); return; }
    if (password.length < 8) { res.status(400).json({ error: 'Password must be at least 8 characters' }); return; }
    const config = loadConfig();
    if (!['json', 'manual'].includes(config.dataSource.type)) { res.status(409).json({ error: 'Manage passwords in the configured source system' }); return; }
    try {
      audit('holder.password.change', res.locals.actor ?? 'admin', holderId);
      const ok = setHolderPassword(config.dataSource.path ?? './data/manual_holders.json', holderId, password);
      res.json({ success: ok });
    } catch { res.status(503).json({ error: 'Holder source unavailable' }); }
  });

  router.get('/admin', requireAdmin, (_req, res) => {
    res.redirect('/console/dashboard');
  });

  router.get('/admin/api/holders', requireAdmin, async (req, res) => {
    try {
      const identifier = typeof req.query.identifier === 'string' ? req.query.identifier : undefined;
      const options = pageBounds({ limit: req.query.limit === undefined ? undefined : Number(req.query.limit), offset: req.query.offset === undefined ? undefined : Number(req.query.offset) });
      let holders: Record<string, unknown>[];
      if (identifier) { const holder = await connector.lookup(identifier); holders = holder ? [holder] : []; }
      else { if (!connector.list) throw new ListingUnavailableError(); holders = await connector.list(options); }
      const counts: Record<string, number> = {};
      for (const credential of getIssuedCredentials().filter(activeCredential)) counts[credential.holderEmail] = (counts[credential.holderEmail] ?? 0) + 1;
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('X-Page-Limit', String(options.limit));
      res.json(holders.map(holder => {
        const record = process.env.PII_ADMIN_MODE === 'true' ? { ...holder } : maskHolderRecord(holder);
        for (const key of Object.keys(record)) if (/password|secret|token|credential/i.test(key)) delete record[key];
        return { ...record, hasCustomPassword: Boolean(holder.customPassword), credentialCount: counts[String(holder.email)] ?? 0 };
      }));
    } catch (error) {
      res.status(error instanceof ListingUnavailableError ? 501 : 503).json({ error: error instanceof ListingUnavailableError ? error.message : 'Holder source unavailable or invalid pagination' });
    }
  });
  router.get('/admin/api/stats', requireAdmin, async (_req, res) => {
    try {
      const credentials = getIssuedCredentials();
      let holders: Record<string, unknown>[] | null = null;
      try { holders = connector.list ? await connector.list({ limit: 1000 }) : null; }
      catch (error) { if (!(error instanceof ListingUnavailableError)) throw error; }
      res.json({
        ...getRuntimeStats(),
        regions: holders ? groupByRegion(holders) : null,
        holderStatistics: { available: holders !== null, sampled: holders?.length === 1000, limit: 1000 },
        credentials: { total: credentials.length, active: credentials.filter(activeCredential).length, revoked: credentials.filter(c => c.revoked).length, expiryUnknown: credentials.filter(c => !c.revoked && !c.expiresAt).length },
      });
    } catch { res.status(503).json({ error: 'Source statistics unavailable' }); }
  });

  // Read-only: list available credential templates
  router.get('/admin/templates', requireAdmin, (_req, res) => {
    res.json({ templates: listTemplates() });
  });

  router.get('/admin/api/config', requireAdmin, (_req, res) => {
    const config = loadConfig();
    res.json({
      revision: config.revision,
      type: config.credential.type,
      fieldMappings: resolveTemplateConfig(config, config.credential.type).fieldMappings,
      dataSourceType: config.dataSource.type,
      templateMappings: config.templateMappings ?? {},
      templateOptionsByType: config.templateOptionsByType ?? {},
    });
  });

  router.post('/admin/api/save-mapping', requireAdmin, requireCsrf, (req, res) => {
    const { templateId, fieldMappings, revision } = (req.body ?? {}) as { templateId?: string; fieldMappings?: Record<string, string>; revision?: number };
    if (!templateId || !fieldMappings) {
      res.status(400).json({ error: 'templateId and fieldMappings are required' });
      return;
    }

    // 1. Dry-run template existence validation
    let template;
    try {
      template = getTemplate(templateId);
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
      return;
    }

    // 2. Validate field mappings against template requirements
    const validationErrors = template.validateMappings(fieldMappings);
    if (validationErrors.length > 0) {
      res.status(400).json({ error: 'Invalid mappings', details: validationErrors });
      return;
    }

    // 3. Persist to vericred.config.json atomically
    try {
      const config = loadConfig();
      if (revision !== undefined && revision !== config.revision) throw new ConfigConflictError();
      selectTemplate(config, templateId, fieldMappings);

      const validated = validateConfig(config);
      audit('config.mapping.change', res.locals.actor ?? 'admin', templateId);
      const saved = saveConfig(validated, config.revision ?? 0);
      res.json({ success: true, revision: saved.revision, message: `Configuration for ${templateId} successfully persisted!` });
    } catch (err) {
      if (err instanceof ConfigConflictError) { res.status(409).json({ error: 'configuration_changed', detail: err.message }); return; }
      res.status(500).json({ error: 'Failed to write configuration: ' + (err as Error).message });
    }
  });

  router.get('/admin/api/csrf-handshake', requireAdmin, (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    const sessionId = getSessionId(req) ?? '';
    const csrfToken = createCsrfToken(sessionId);
    res.json({ csrfToken });
  });

  return router;
}
