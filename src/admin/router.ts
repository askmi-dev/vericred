import { writeFileSync } from 'fs';
import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { requireAdmin } from '../middleware/auth.js';
import { getRuntimeStats, getUptime } from './runtime.js';
import { getIssuedCredentials } from '../revocation/statuslist.js';
import { loadSecrets } from '../config/secrets.js';
import { createSession, destroySession, createCsrfToken, requireCsrf, cookieFlags, getSessionId } from '../middleware/auth.js';
import { setHolderPassword, formatInTimezone, readHolders, REGIONS, REGION_TIMEZONE } from '../connectors/generator.js';
import type { HolderRecord } from '../connectors/generator.js';
import { listTemplates, getTemplate } from '../credentials/registry.js';
import { maskHolderRecord } from './masking.js';
import { loadConfig } from '../config/loader.js';
import type { Connector } from '../connectors/index.js';
import { getIssuerKeyPair, rotateIssuerKeyPair, getAllPublicKeys } from '../keys/manager.js';
import { calculateJwkThumbprint, exportJWK } from 'jose';
import { getInteropLogs } from '../oid4vci/interop-logger.js';
// Register templates so they appear in listTemplates()
import '../credentials/templates/age.js';
import '../credentials/templates/employee.js';
import '../credentials/templates/membership.js';

const DATA_DIR = process.env.DATA_DIR ?? '.';
const DATA_PATH = `${DATA_DIR}/holders.json`;
const CONFIG_PATH = `${DATA_DIR}/vericred.config.json`;

function groupByRegion(holders: HolderRecord[]) {
  return holders.reduce<Record<string, number>>((acc, h) => {
    acc[h.region] = (acc[h.region] ?? 0) + 1;
    return acc;
  }, {});
}


function maskEmail(email: string): string {
  const [user, domain] = email.split('@');
  if (!domain) return '***';
  const visible = user.length > 3 ? user.slice(0, 3) : user.slice(0, 1);
  return visible + '***@' + domain;
}

export function createAdminRouter(connector: Connector): Router {
  const router = createRouter();

  router.get('/admin/api/setup-status', requireAdmin, (_req, res) => {
    const config = loadConfig();
    // Default name is 'VeriCred Issuer'. If it's still that, we're likely unconfigured.
    const isUnconfigured = config.issuer.name === 'VeriCred Issuer';
    res.json({ isUnconfigured });
  });

  router.post('/admin/api/setup', requireAdmin, requireCsrf, (req, res) => {
    const { name, url, dataSource } = req.body as { name?: string; url?: string; dataSource?: any };
    if (!name || !url) {
      res.status(400).json({ error: 'Issuer name and URL are required' });
      return;
    }

    try {
      const config = loadConfig();
      config.issuer.name = name;
      config.issuer.url = url;
      config.issuer.did = `did:web:${new URL(url).host}`;
      if (dataSource) config.dataSource = dataSource;

      writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
      res.json({ success: true, message: 'Initial configuration saved successfully!' });
    } catch (err) {
      res.status(500).json({ error: 'Failed to save setup: ' + (err as Error).message });
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
      const newKey = await rotateIssuerKeyPair();
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
      res.status(500).json({ error: 'failed to fetch source schema' });
    }
  });

  router.get('/admin/login', (_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send('<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><title>VeriCred Admin</title>'
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
    if (!holderId || !password) { res.status(400).json({ error: 'holderId and password required' }); return; }
    if (password.length < 8) { res.status(400).json({ error: 'Password must be at least 8 characters' }); return; }
    const ok = setHolderPassword(DATA_PATH, holderId, password);
    res.json({ success: ok });
  });

  router.get('/admin', requireAdmin, (_req, res) => {
    res.redirect('/console/dashboard');
  });

  router.get('/admin/api/holders', requireAdmin, (_req, res) => {
    const holders = readHolders(DATA_PATH);
    if (process.env['PII_ADMIN_MODE'] === 'true') {
      res.json(holders);
    } else {
      res.json(holders.map(h => maskHolderRecord(h as unknown as Record<string, unknown>)));
    }
  });
  router.get('/admin/api/stats', requireAdmin, (_req, res) => {
    const creds = getIssuedCredentials();
    res.json({
      ...getRuntimeStats(),
      regions: groupByRegion(readHolders(DATA_PATH)),
      credentials: { total: creds.length, active: creds.filter(c => !c.revoked).length, revoked: creds.filter(c => c.revoked).length },
    });
  });

  // Read-only: list available credential templates
  router.get('/admin/templates', requireAdmin, (_req, res) => {
    res.json({ templates: listTemplates() });
  });

  router.get('/admin/api/config', requireAdmin, (_req, res) => {
    const config = loadConfig();
    res.json({
      type: config.credential.type,
      fieldMappings: config.fieldMappings,
      dataSourceType: config.dataSource.type,
    });
  });

  router.post('/admin/api/save-mapping', requireAdmin, requireCsrf, (req, res) => {
    const { templateId, fieldMappings } = req.body as { templateId?: string; fieldMappings?: Record<string, string> };
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
      config.credential.type = templateId;
      config.fieldMappings = fieldMappings;

      const CONFIG_PATH = `${DATA_DIR}/vericred.config.json`;
      writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf-8');
      res.json({ success: true, message: `Configuration for ${templateId} successfully persisted!` });
    } catch (err) {
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
