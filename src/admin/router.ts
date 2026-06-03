import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { readFileSync, existsSync } from 'fs';
import { requireAdmin } from '../middleware/auth.js';
import { getRuntimeStats, getUptime } from './runtime.js';
import { getIssuedCredentials } from '../revocation/statuslist.js';
import { loadSecrets } from '../config/secrets.js';
import { setHolderPassword, setHolderTimezone, formatInTimezone, SUPPORTED_TIMEZONES } from '../connectors/generator.js';
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

  // ── Login page ──────────────────────────────────────────────────────────────
  router.get('/admin/login', (_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8"><title>VeriCred Admin</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
  .card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;width:360px}
  h1{font-size:1.4rem;margin-bottom:.25rem;color:#f1f5f9}
  p{font-size:.85rem;color:#94a3b8;margin-bottom:1.5rem}
  input{width:100%;padding:.6rem .8rem;background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0;font-size:.9rem;margin-bottom:1rem}
  button{width:100%;padding:.7rem;background:#6366f1;border:none;border-radius:6px;color:white;font-size:.95rem;cursor:pointer}
  button:hover{background:#4f46e5}
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
</body></html>`);
  });

  // ── Login POST ──────────────────────────────────────────────────────────────
  router.post('/admin/login', (req, res) => {
    const { apiKey } = req.body as { apiKey: string };
    if (apiKey === loadSecrets().adminApiKey) {
      res.setHeader('Set-Cookie', `admin_session=${apiKey}; HttpOnly; Path=/; SameSite=Strict`);
      res.redirect('/admin');
      return;
    }
    res.redirect('/admin/login?err=1');
  });

  // ── Logout ──────────────────────────────────────────────────────────────────
  router.get('/admin/logout', (_req, res) => {
    res.setHeader('Set-Cookie', 'admin_session=; HttpOnly; Path=/; Max-Age=0');
    res.redirect('/admin/login');
  });

  // ── Password update API ─────────────────────────────────────────────────────
  router.post('/admin/holder/password', requireAdmin, (req, res) => {
    const { holderId, password } = req.body as { holderId?: string; password?: string };
    if (!holderId || !password) { res.status(400).json({ error: 'holderId and password required' }); return; }
    if (password.length < 8) { res.status(400).json({ error: 'Password must be at least 8 characters' }); return; }
    const ok = setHolderPassword(DATA_PATH, holderId, password);
    res.json({ success: ok });
  });


  // ── Timezone update API ─────────────────────────────────────────────────────
  router.post('/admin/holder/timezone', requireAdmin, (req, res) => {
    const { holderId, timezone } = req.body as { holderId?: string; timezone?: string };
    if (!holderId || !timezone) { res.status(400).json({ error: 'holderId and timezone required' }); return; }
    const ok = setHolderTimezone(DATA_PATH, holderId, timezone);
    res.json({ success: ok, error: ok ? undefined : 'Invalid timezone or holder not found' });
  });

  // ── Dashboard ───────────────────────────────────────────────────────────────
  router.get('/admin', requireAdmin, (req, res) => {
    const allHolders = getHolders();
    const stats = getRuntimeStats();
    const credentials = getIssuedCredentials();

    // Date filter
    const filter = (req.query['filter'] as string) ?? 'all';
    const now = new Date();
    const cutoff: Record<string, Date> = {
      today: new Date(now.toISOString().slice(0, 10)),
      week: new Date(now.getTime() - 7 * 86400000),
      month: new Date(now.getTime() - 30 * 86400000),
    };
    const holders = filter === 'all' ? allHolders
      : allHolders.filter(h => h.createdAt && new Date(h.createdAt) >= cutoff[filter]);

    const today = now.toISOString().slice(0, 10);
    const todayHolders = allHolders.filter(h => h.createdAt?.startsWith(today));
    const activeCredentials = credentials.filter(c => !c.revoked).length;
    const revokedCredentials = credentials.filter(c => c.revoked).length;
    const todayCredentials = credentials.filter(c => c.issuedAt?.startsWith(today)).length;

    const regions = groupByRegion(holders);
    const regionRows = Object.entries(regions)
      .sort((a, b) => b[1] - a[1])
      .map(([r, n]) => `<tr><td>${r}</td><td>${n}</td></tr>`)
      .join('');

    const holderRows = holders.slice(-100).reverse().map(h => {
      const pw = h.customPassword ?? h.defaultPassword;
      const tz = h.timezone ?? 'Europe/Vienna';
      const localTime = h.createdAt ? formatInTimezone(h.createdAt, tz) : '—';
      const emailSubject = encodeURIComponent('Dein VeriCred Zugang');
      const emailBody = encodeURIComponent(`Hallo ${h.firstName},\n\ndein VeriCred-Passwort wurde zurückgesetzt.\n\nNeues Passwort: ${pw}\n\nBitte ändere es nach dem ersten Login.\n\nVeriCred`);
      const tzSelect = SUPPORTED_TIMEZONES.map(t =>
        `<option value="${t}"${tz === t ? ' selected' : ''}>${t.replace('Europe/', '')}</option>`
      ).join('');
      return `<tr>
        <td style="font-size:.75rem;color:#94a3b8">${h.id.slice(-8)}</td>
        <td>${h.firstName} ${h.lastName}</td>
        <td style="font-size:.8rem">${h.email}</td>
        <td>${h.region}</td>
        <td>
          <select id="tz-${h.id}" onchange="changeTz('${h.id}',this.value)" style="background:#0f172a;border:1px solid #334155;color:#e2e8f0;border-radius:4px;font-size:.75rem;padding:2px 4px">${tzSelect}</select>
        </td>
        <td>
          <span id="pw-${h.id}" style="font-family:monospace;font-size:.8rem;background:#0f172a;padding:2px 6px;border-radius:4px">${pw}</span>
          <button onclick="editPw('${h.id}','${h.email}')" style="margin-left:6px;background:#334155;border:none;color:#94a3b8;padding:2px 8px;border-radius:4px;cursor:pointer;font-size:.75rem">✏️</button>
          <a href="mailto:${h.email}?subject=${emailSubject}&body=${emailBody}" style="margin-left:4px;font-size:.75rem;color:#6366f1">✉️</a>
        </td>
        <td style="font-size:.75rem;color:#94a3b8">${localTime}</td>
      </tr>`;
    }).join('');

    const credRows = credentials.slice(-100).reverse().map(c => `
      <tr>
        <td style="font-size:.75rem;color:#94a3b8">${c.credentialId.slice(-12)}</td>
        <td>${c.holderEmail}</td>
        <td style="font-size:.75rem">${c.issuedAt.slice(0, 16).replace('T', ' ')}</td>
        <td style="color:${c.revoked ? '#f87171' : '#4ade80'}">${c.revoked ? '⛔ Revoked' : '✅ Active'}</td>
        <td>${c.revoked ? `<span style="font-size:.75rem;color:#64748b">${c.revokedAt?.slice(0,16).replace('T',' ') ?? ''}</span>` : `<button onclick="revoke('${c.credentialId}')" style="background:#ef4444;border:none;color:white;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:.8rem">Revoke</button>`}</td>
      </tr>`).join('');

    const filterBtn = (val: string, label: string) =>
      `<a href="/admin?filter=${val}" style="padding:4px 12px;border-radius:20px;font-size:.8rem;text-decoration:none;${filter === val ? 'background:#6366f1;color:white' : 'background:#1e293b;color:#94a3b8;border:1px solid #334155'}">${label}</a>`;

    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="de">
<head><meta charset="UTF-8"><title>VeriCred Admin</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
  h1{font-size:1.5rem;margin-bottom:.25rem}
  .sub{color:#64748b;margin-bottom:1.5rem;font-size:.9rem}
  .stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2rem}
  .stat{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1.2rem}
  .stat .num{font-size:2rem;font-weight:700;color:#6366f1}
  .stat .label{font-size:.8rem;color:#94a3b8;margin-top:.2rem}
  .stat.green .num{color:#4ade80}
  .stat.red .num{color:#f87171}
  .grid2{display:grid;grid-template-columns:1fr 2fr;gap:1.5rem;margin-bottom:1.5rem}
  .box{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1.2rem;margin-bottom:1.5rem}
  h2{font-size:1rem;margin-bottom:1rem;color:#cbd5e1}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;padding:.5rem;color:#64748b;border-bottom:1px solid #334155}
  td{padding:.5rem;border-bottom:1px solid #1e293b}
  tr:hover td{background:#263248}
  .filters{display:flex;gap:.5rem;margin-bottom:1rem}
  a.logout{float:right;color:#64748b;font-size:.85rem;text-decoration:none}
</style>
</head>
<body>
<h1>🎫 VeriCred Admin <a class="logout" href="/admin/logout">Logout</a></h1>
<p class="sub">Issuer-Übersicht · Nur intern sichtbar</p>

<div class="stats">
  <div class="stat"><div class="num">${allHolders.length}</div><div class="label">Holder gesamt</div></div>
  <div class="stat"><div class="num">${todayHolders.length}</div><div class="label">Holder heute</div></div>
  <div class="stat green"><div class="num">${activeCredentials}</div><div class="label">Credentials aktiv</div></div>
  <div class="stat red"><div class="num">${revokedCredentials}</div><div class="label">Revoked</div></div>
  <div class="stat"><div class="num">${getUptime()}</div><div class="label">Uptime (${stats.totalRestarts} Starts)</div></div>
</div>

<div class="grid2">
  <div class="box">
    <h2>Regionen</h2>
    <table><tr><th>Region</th><th>Holder</th></tr>${regionRows}</table>
  </div>
  <div class="box">
    <h2>Holder</h2>
    <div class="filters">
      ${filterBtn('today', 'Heute')}
      ${filterBtn('week', 'Diese Woche')}
      ${filterBtn('month', 'Dieser Monat')}
      ${filterBtn('all', 'Alle')}
      <span style="margin-left:auto;font-size:.8rem;color:#64748b">${holders.length} Einträge</span>
    </div>
    <table>
      <tr><th>ID</th><th>Name</th><th>Email</th><th>Region</th><th>Zeitzone</th><th>Passwort</th><th>Erstellt (lokal)</th></tr>
      ${holderRows}
    </table>
  </div>
</div>

<div class="box">
  <h2>Credentials — heute ${todayCredentials} ausgestellt</h2>
  <table>
    <tr><th>ID</th><th>Holder</th><th>Ausgestellt</th><th>Status</th><th></th></tr>
    ${credRows}
  </table>
</div>

<script>
async function revoke(credentialId) {
  if (!confirm('Credential wirklich revoken?')) return;
  const r = await fetch('/admin/revoke', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({credentialId})});
  const d = await r.json();
  alert(d.message);
  location.reload();
}
async function editPw(holderId, email) {
  const newPw = prompt('Neues Passwort für ' + email + ' (min. 8 Zeichen):');
  if (!newPw || newPw.length < 8) return;
  const r = await fetch('/admin/holder/password', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({holderId,password:newPw})});
  const d = await r.json();
  if (d.success) { document.getElementById('pw-' + holderId).textContent = newPw; }
  else { alert('Fehler beim Speichern'); }
}
async function changeTz(holderId, timezone) {
  const r = await fetch('/admin/holder/timezone', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({holderId,timezone})});
  const d = await r.json();
  if (d.success) { location.reload(); }
  else { alert('Fehler: ' + (d.error ?? 'Unbekannt')); }
}
</script>
</body></html>`);
  });

  // ── JSON API ─────────────────────────────────────────────────────────────────
  router.get('/admin/api/holders', requireAdmin, (_req, res) => res.json(getHolders()));
  router.get('/admin/api/stats', requireAdmin, (_req, res) => {
    const creds = getIssuedCredentials();
    res.json({
      ...getRuntimeStats(),
      regions: groupByRegion(getHolders()),
      credentials: { total: creds.length, active: creds.filter(c => !c.revoked).length, revoked: creds.filter(c => c.revoked).length },
    });
  });

  return router;
}
