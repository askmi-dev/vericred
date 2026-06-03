import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { readFileSync, existsSync } from 'fs';
import { requireAdmin } from '../middleware/auth.js';
import { getRuntimeStats, getUptime } from './runtime.js';
import { loadSecrets } from '../config/secrets.js';
import type { HolderRecord } from '../connectors/generator.js';

const DATA_PATH = './data/holders.json';

function getHolders(): HolderRecord[] {
  return existsSync(DATA_PATH) ? JSON.parse(readFileSync(DATA_PATH, 'utf-8')) : [];
}

function groupByRegion(holders: HolderRecord[]) {
  return holders.reduce<Record<string, number>>((acc, h) => {
    acc[h.region] = (acc[h.region] ?? 0) + 1;
    return acc;
  }, {});
}

export function createAdminRouter(): Router {
  const router = createRouter();

  // Login page
  router.get('/admin/login', (_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8"><title>VeriCred Admin</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; width: 360px; }
  h1 { font-size: 1.4rem; margin-bottom: 0.25rem; color: #f1f5f9; }
  p { font-size: 0.85rem; color: #94a3b8; margin-bottom: 1.5rem; }
  input { width: 100%; padding: 0.6rem 0.8rem; background: #0f172a; border: 1px solid #334155; border-radius: 6px; color: #e2e8f0; font-size: 0.9rem; margin-bottom: 1rem; }
  button { width: 100%; padding: 0.7rem; background: #6366f1; border: none; border-radius: 6px; color: white; font-size: 0.95rem; cursor: pointer; }
  button:hover { background: #4f46e5; }
  .err { color: #f87171; font-size: 0.8rem; margin-top: 0.5rem; }
</style>
</head>
<body>
<div class="card">
  <h1>🎫 VeriCred</h1>
  <p>Admin-Zugang — API-Key aus dem Terminal beim ersten Start</p>
  <form method="POST" action="/admin/login">
    <input type="password" name="apiKey" placeholder="Admin API Key" autofocus required />
    <button type="submit">Einloggen</button>
  </form>
</div>
</body>
</html>`);
  });

  // Login POST
  router.post('/admin/login', (req, res) => {
    const { apiKey } = req.body as { apiKey: string };
    const secrets = loadSecrets();
    if (apiKey === secrets.adminApiKey) {
      res.setHeader('Set-Cookie', `admin_session=${apiKey}; HttpOnly; Path=/; SameSite=Strict`);
      res.redirect('/admin');
      return;
    }
    res.redirect('/admin/login?err=1');
  });

  // Logout
  router.get('/admin/logout', (_req, res) => {
    res.setHeader('Set-Cookie', 'admin_session=; HttpOnly; Path=/; Max-Age=0');
    res.redirect('/admin/login');
  });

  // Dashboard
  router.get('/admin', requireAdmin, (_req, res) => {
    const holders = getHolders();
    const stats = getRuntimeStats();
    const regions = groupByRegion(holders);
    const today = new Date().toISOString().slice(0, 10);
    const todayHolders = holders.filter(h => h.createdAt?.startsWith(today));

    const regionRows = Object.entries(regions)
      .sort((a, b) => b[1] - a[1])
      .map(([r, n]) => `<tr><td>${r}</td><td>${n}</td></tr>`)
      .join('');

    const holderRows = holders.slice(-50).reverse().map(h => `
      <tr>
        <td style="font-size:0.75rem;color:#94a3b8">${h.id.slice(-8)}</td>
        <td>${h.firstName} ${h.lastName}</td>
        <td>${h.email}</td>
        <td>${h.region}</td>
        <td><code style="background:#0f172a;padding:2px 6px;border-radius:4px;font-size:0.8rem">${h.defaultPassword}</code></td>
        <td style="font-size:0.75rem;color:#94a3b8">${h.createdAt?.slice(0, 16).replace('T', ' ') ?? '—'}</td>
      </tr>`).join('');

    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8"><title>VeriCred Admin</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }
  h1 { font-size: 1.5rem; margin-bottom: 0.25rem; }
  .subtitle { color: #64748b; margin-bottom: 2rem; font-size: 0.9rem; }
  .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1.2rem; }
  .stat .num { font-size: 2rem; font-weight: 700; color: #6366f1; }
  .stat .label { font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem; }
  .grid2 { display: grid; grid-template-columns: 1fr 2fr; gap: 1.5rem; margin-bottom: 2rem; }
  .box { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 1.2rem; }
  h2 { font-size: 1rem; margin-bottom: 1rem; color: #cbd5e1; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { text-align: left; padding: 0.5rem; color: #64748b; border-bottom: 1px solid #334155; }
  td { padding: 0.5rem; border-bottom: 1px solid #1e293b; }
  tr:hover td { background: #1e293b; }
  a { color: #6366f1; text-decoration: none; font-size: 0.85rem; }
  .logout { float: right; color: #64748b; }
</style>
</head>
<body>
<h1>🎫 VeriCred Admin <a class="logout" href="/admin/logout">Logout</a></h1>
<p class="subtitle">Issuer-Übersicht · Letzte 50 Holder · Nur intern sichtbar</p>

<div class="stats">
  <div class="stat"><div class="num">${holders.length}</div><div class="label">Holder gesamt</div></div>
  <div class="stat"><div class="num">${todayHolders.length}</div><div class="label">Heute neu</div></div>
  <div class="stat"><div class="num">${stats.todayRestarts}</div><div class="label">Restarts heute</div></div>
  <div class="stat"><div class="num">${stats.totalRestarts}</div><div class="label">Restarts gesamt</div></div>
  <div class="stat"><div class="num">${getUptime()}</div><div class="label">Uptime</div></div>
</div>

<div class="grid2">
  <div class="box">
    <h2>Regionen</h2>
    <table><tr><th>Region</th><th>Holder</th></tr>${regionRows}</table>
  </div>
  <div class="box">
    <h2>Letzte Holder (max. 50)</h2>
    <table>
      <tr><th>ID</th><th>Name</th><th>Email</th><th>Region</th><th>Default-PW</th><th>Erstellt</th></tr>
      ${holderRows}
    </table>
  </div>
</div>
</body>
</html>`);
  });

  // JSON API endpoints (for programmatic access)
  router.get('/admin/api/holders', requireAdmin, (_req, res) => {
    res.json(getHolders());
  });

  router.get('/admin/api/stats', requireAdmin, (_req, res) => {
    res.json({ ...getRuntimeStats(), regions: groupByRegion(getHolders()) });
  });

  return router;
}
