import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { requireAdmin } from '../middleware/auth.js';
import { getRuntimeStats, getUptime } from './runtime.js';
import { getIssuedCredentials } from '../revocation/statuslist.js';
import { loadSecrets } from '../config/secrets.js';
import { createSession, destroySession, createCsrfToken, requireCsrf, cookieFlags } from '../middleware/auth.js';
import { setHolderPassword, formatInTimezone, readHolders, REGIONS, REGION_TIMEZONE } from '../connectors/generator.js';
import type { HolderRecord } from '../connectors/generator.js';

const DATA_PATH = './data/holders.json';

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

export function createAdminRouter(): Router {
  const router = createRouter();

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
      res.redirect('/admin');
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

  router.get('/admin', requireAdmin, (req, res) => {
    const allHolders = readHolders(DATA_PATH);
    const credentials = getIssuedCredentials();
    const stats = getRuntimeStats();
    const q = req.query as Record<string, string>;
    const csrf = createCsrfToken();
    const now = new Date();
    const today = now.toISOString().slice(0, 10);

    const dateFilter = q['date'] ?? 'all';
    const cutoff: Record<string, Date> = {
      today: new Date(today),
      week: new Date(now.getTime() - 7 * 86400000),
      month: new Date(now.getTime() - 30 * 86400000),
    };
    let holders = dateFilter === 'all' ? allHolders
      : allHolders.filter(h => h.createdAt && new Date(h.createdAt) >= cutoff[dateFilter]);

    const regionFilter = q['region'] ?? '';
    if (regionFilter) holders = holders.filter(h => h.region === regionFilter);

    const search = (q['q'] ?? '').toLowerCase().trim();
    if (search) holders = holders.filter(h =>
      (h.firstName + ' ' + h.lastName).toLowerCase().includes(search) ||
      h.email.toLowerCase().includes(search)
    );

    const sortCol = q['sort'] ?? 'date';
    const sortDir = q['dir'] === 'asc' ? 1 : -1;
    holders = [...holders].sort((a, b) => {
      switch (sortCol) {
        case 'name':   return sortDir * (a.firstName + ' ' + a.lastName).localeCompare(b.firstName + ' ' + b.lastName);
        case 'email':  return sortDir * a.email.localeCompare(b.email);
        case 'region': return sortDir * a.region.localeCompare(b.region);
        default:       return sortDir * ((a.createdAt ?? '') < (b.createdAt ?? '') ? -1 : 1);
      }
    });

    const todayHolders = allHolders.filter(h => h.createdAt?.startsWith(today));
    const activeCredentials = credentials.filter(c => !c.revoked).length;
    const revokedCredentials = credentials.filter(c => c.revoked).length;
    const todayCredentials = credentials.filter(c => c.issuedAt?.startsWith(today)).length;

    const credByHolder: Record<string, number> = {};
    for (const c of credentials) {
      if (!c.revoked) credByHolder[c.holderEmail] = (credByHolder[c.holderEmail] ?? 0) + 1;
    }

    function sortLink(col: string, label: string) {
      const active = sortCol === col;
      const arrow = active ? (sortDir === 1 ? ' up' : ' down') : '';
      const nextDir = active && sortDir === -1 ? 'asc' : 'desc';
      const p = new URLSearchParams({ ...q, sort: col, dir: nextDir });
      return '<th style="cursor:pointer;white-space:nowrap" onclick="location.href=\'?' + p + '\'">' + label + arrow + '</th>';
    }

    const regionGroups = groupByRegion(allHolders);
    const regionRows = Object.entries(regionGroups)
      .sort((a, b) => b[1] - a[1])
      .map(([r, n]) => {
        const p = new URLSearchParams({ ...q, region: r });
        return '<tr><td><a href="?' + p + '" style="color:#94a3b8;text-decoration:none">' + r + '</a></td><td>' + n + '</td></tr>';
      }).join('');

    const displayed = holders.slice(0, 200);
    const holderRows = displayed.map(h => {
      const hasPw = !!h.customPassword;
      const tz = h.timezone ?? REGION_TIMEZONE[h.region] ?? 'Europe/Vienna';
      const localTime = h.createdAt ? formatInTimezone(h.createdAt, tz) : '-';
      const credCount = credByHolder[h.email] ?? 0;
      const subj = encodeURIComponent('Dein VeriCred Zugang');
      const body = encodeURIComponent('Hallo ' + h.firstName + ',\n\nDein Passwort wurde zurueckgesetzt. Bitte melde dich an.\n\nVeriCred');
      const rp = new URLSearchParams({ ...q, region: h.region });
      return '<tr>'
        + '<td style="font-size:.75rem;color:#94a3b8">' + h.id.slice(-8) + '</td>'
        + '<td>' + h.firstName + ' ' + h.lastName + '</td>'
        + '<td style="font-size:.8rem;font-family:monospace">' + (process.env['PII_ADMIN_MODE'] === 'true' ? h.email : maskEmail(h.email)) + '</td>'
        + '<td><a href="?' + rp + '" style="color:#94a3b8;text-decoration:none">' + h.region + '</a></td>'
        + '<td style="font-size:.75rem;color:#94a3b8;white-space:nowrap">' + localTime + '</td>'
        + '<td style="text-align:center">' + (credCount > 0
            ? '<span style="background:#1a3a2a;color:#4ade80;padding:1px 8px;border-radius:10px;font-size:.75rem">' + credCount + '</span>'
            : '<span style="color:#475569;font-size:.75rem">-</span>') + '</td>'
        + '<td style="white-space:nowrap">'
        + '<span style="font-size:.75rem;color:' + (hasPw ? '#4ade80' : '#475569') + '">' + (hasPw ? 'Eigenes Pw' : 'Standard Pw') + '</span>'
        + '<button onclick="editPw(\'' + h.id + '\',\'' + h.email + '\')" style="margin-left:8px;background:#334155;border:none;color:#94a3b8;padding:2px 8px;border-radius:4px;cursor:pointer;font-size:.75rem">Setzen</button>'
        + '<a href="mailto:' + h.email + '?subject=' + subj + '&body=' + body + '" style="margin-left:4px;font-size:.75rem;color:#6366f1">Mail</a>'
        + '</td></tr>';
    }).join('');

    const credFilter = q['cred'] ?? 'all';
    let filteredCreds = credentials;
    if (credFilter === 'active') filteredCreds = credentials.filter(c => !c.revoked);
    if (credFilter === 'revoked') filteredCreds = credentials.filter(c => c.revoked);

    const credRows = filteredCreds.slice(-200).reverse().map(c =>
      '<tr>'
      + '<td style="font-size:.75rem;color:#94a3b8">' + c.credentialId.slice(-12) + '</td>'
      + '<td style="font-family:monospace">' + (process.env['PII_ADMIN_MODE'] === 'true' ? c.holderEmail : maskEmail(c.holderEmail)) + '</td>'
      + '<td style="font-size:.75rem">' + c.issuedAt.slice(0, 16).replace('T', ' ') + '</td>'
      + '<td style="color:' + (c.revoked ? '#f87171' : '#4ade80') + '">' + (c.revoked ? 'Revoked' : 'Active') + '</td>'
      + '<td>' + (c.revoked
          ? '<span style="font-size:.75rem;color:#64748b">' + (c.revokedAt?.slice(0, 16).replace('T', ' ') ?? '') + '</span>'
          : '<button onclick="revoke(\'' + c.credentialId + '\')" style="background:#ef4444;border:none;color:white;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:.8rem">Revoke</button>')
      + '</td></tr>'
    ).join('');

    function chip(param: string, val: string, label: string, current: string) {
      const active = current === val || (!val && (current === 'all' || !current));
      const p = new URLSearchParams({ ...q });
      if (val) p.set(param, val); else p.delete(param);
      return '<a href="?' + p + '" style="padding:4px 12px;border-radius:20px;font-size:.8rem;text-decoration:none;'
        + (active ? 'background:#6366f1;color:white' : 'background:#1e293b;color:#94a3b8;border:1px solid #334155')
        + '">' + label + '</a>';
    }

    const regionOptions = REGIONS.map(r =>
      '<option value="' + r + '"' + (regionFilter === r ? ' selected' : '') + '>' + r + '</option>'
    ).join('');

    const hasFilters = search || regionFilter || dateFilter !== 'all';

    const CSS = '*{box-sizing:border-box;margin:0;padding:0}'
      + 'body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}'
      + 'h1{font-size:1.5rem;margin-bottom:.25rem}'
      + '.sub{color:#64748b;margin-bottom:1.5rem;font-size:.9rem}'
      + '.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2rem}'
      + '.stat{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1.2rem}'
      + '.stat .num{font-size:2rem;font-weight:700;color:#6366f1}'
      + '.stat .label{font-size:.8rem;color:#94a3b8;margin-top:.2rem}'
      + '.stat.green .num{color:#4ade80}.stat.red .num{color:#f87171}'
      + '.grid2{display:grid;grid-template-columns:220px 1fr;gap:1.5rem;margin-bottom:1.5rem}'
      + '.box{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:1.2rem;margin-bottom:1.5rem}'
      + 'h2{font-size:1rem;margin-bottom:1rem;color:#cbd5e1}'
      + 'table{width:100%;border-collapse:collapse;font-size:.85rem}'
      + 'th{text-align:left;padding:.5rem;color:#64748b;border-bottom:1px solid #334155;user-select:none}'
      + 'th:hover{color:#cbd5e1}'
      + 'td{padding:.5rem;border-bottom:1px solid #1e293b;vertical-align:middle}'
      + 'tr:hover td{background:#263248}'
      + '.toolbar{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin-bottom:1rem}'
      + '.si{background:#0f172a;border:1px solid #334155;border-radius:6px;color:#e2e8f0;padding:5px 10px;font-size:.85rem;width:200px}'
      + '.si:focus{outline:none;border-color:#6366f1}'
      + 'select.sel{background:#0f172a;border:1px solid #334155;color:#e2e8f0;border-radius:6px;padding:5px 8px;font-size:.85rem;cursor:pointer}'
      + 'a.logout{float:right;color:#64748b;font-size:.85rem;text-decoration:none}'
      + '.cl{font-size:.75rem;color:#475569;text-decoration:none;padding:4px 8px;border:1px solid #334155;border-radius:4px}'
      + '.cl:hover{color:#94a3b8}';

    res.setHeader('Content-Type', 'text/html');
    res.send('<!DOCTYPE html><html lang="de"><head><meta charset="UTF-8"><title>VeriCred Admin</title>'
      + '<style>' + CSS + '</style></head><body>'
      + '<h1>VeriCred Admin <a class="logout" href="/admin/logout">Logout</a></h1>'
      + '<p class="sub">Issuer-Uebersicht - Nur intern sichtbar</p>'
      + '<div class="stats">'
      + '<div class="stat"><div class="num">' + allHolders.length + '</div><div class="label">Holder gesamt</div></div>'
      + '<div class="stat"><div class="num">' + todayHolders.length + '</div><div class="label">Holder heute</div></div>'
      + '<div class="stat green"><div class="num">' + activeCredentials + '</div><div class="label">Credentials aktiv</div></div>'
      + '<div class="stat red"><div class="num">' + revokedCredentials + '</div><div class="label">Revoked</div></div>'
      + '<div class="stat"><div class="num">' + getUptime() + '</div><div class="label">Uptime (' + stats.totalRestarts + ' Starts)</div></div>'
      + '</div>'
      + '<div class="grid2">'
      + '<div class="box"><h2>Regionen</h2>'
      + '<table><tr><th>Region</th><th>#</th></tr>' + regionRows + '</table>'
      + (regionFilter ? '<div style="margin-top:.75rem"><a href="/admin" style="font-size:.75rem;color:#475569;text-decoration:none">x Alle Regionen</a></div>' : '')
      + '</div>'
      + '<div class="box"><h2>Holder</h2>'
      + '<form method="GET" action="/admin" id="hf">'
      + '<input type="hidden" name="sort" value="' + sortCol + '">'
      + '<input type="hidden" name="dir" value="' + (sortDir === 1 ? 'asc' : 'desc') + '">'
      + '<div class="toolbar">'
      + '<input class="si" type="text" name="q" value="' + search.replace(/"/g, '&quot;') + '" placeholder="Name oder E-Mail..." oninput="deb()">'
      + '<select class="sel" name="region" onchange="this.form.submit()"><option value="">Alle Regionen</option>' + regionOptions + '</select>'
      + '<select class="sel" name="date" onchange="this.form.submit()">'
      + '<option value="all"' + (dateFilter === 'all' ? ' selected' : '') + '>Alle Zeiten</option>'
      + '<option value="today"' + (dateFilter === 'today' ? ' selected' : '') + '>Heute</option>'
      + '<option value="week"' + (dateFilter === 'week' ? ' selected' : '') + '>Diese Woche</option>'
      + '<option value="month"' + (dateFilter === 'month' ? ' selected' : '') + '>Dieser Monat</option>'
      + '</select>'
      + (hasFilters ? '<a href="/admin" class="cl">x Filter</a>' : '')
      + '<span style="margin-left:auto;font-size:.8rem;color:#64748b">' + holders.length + ' Ergebnisse' + (holders.length > 200 ? ' - Top 200' : '') + '</span>'
      + '</div></form>'
      + '<table><tr>'
      + sortLink('id', 'ID') + sortLink('name', 'Name') + sortLink('email', 'Email')
      + sortLink('region', 'Region') + sortLink('date', 'Erstellt')
      + '<th style="text-align:center">Creds</th><th>Zugang</th>'
      + '</tr>' + (holderRows || '<tr><td colspan="7" style="text-align:center;color:#475569;padding:2rem">Keine Eintraege</td></tr>') + '</table>'
      + '</div></div>'
      + '<div class="box"><h2>Credentials - heute ' + todayCredentials + ' ausgestellt</h2>'
      + '<div class="toolbar" style="margin-bottom:1rem">'
      + chip('cred', '', 'Alle', credFilter)
      + chip('cred', 'active', 'Aktiv', credFilter)
      + chip('cred', 'revoked', 'Revoked', credFilter)
      + '<span style="margin-left:auto;font-size:.8rem;color:#64748b">' + filteredCreds.length + ' Eintraege</span>'
      + '</div>'
      + '<table><tr><th>ID</th><th>Holder</th><th>Ausgestellt</th><th>Status</th><th></th></tr>'
      + (credRows || '<tr><td colspan="5" style="text-align:center;color:#475569;padding:2rem">Keine Credentials</td></tr>')
      + '</table></div>'
      + '<script>'
      + 'const CSRF="' + csrf + '";'
      + 'let t;function deb(){clearTimeout(t);t=setTimeout(()=>document.getElementById("hf").submit(),350)}'
      + 'async function revoke(id){if(!confirm("Revoken?"))return;const r=await fetch("/admin/revoke",{method:"POST",headers:{"Content-Type":"application/json","x-csrf-token":CSRF},body:JSON.stringify({credentialId:id})});const d=await r.json();alert(d.message);location.reload()}'
      + 'async function editPw(id,email){const p=prompt("Neues Passwort fuer "+email+" (min. 8 Zeichen):");if(!p||p.length<8)return;const r=await fetch("/admin/holder/password",{method:"POST",headers:{"Content-Type":"application/json","x-csrf-token":CSRF},body:JSON.stringify({holderId:id,password:p})});const d=await r.json();if(d.success){location.reload()}else{alert("Fehler")}}'
      + '</script></body></html>');
  });

  router.get('/admin/api/holders', requireAdmin, (_req, res) => res.json(readHolders(DATA_PATH)));
  router.get('/admin/api/stats', requireAdmin, (_req, res) => {
    const creds = getIssuedCredentials();
    res.json({
      ...getRuntimeStats(),
      regions: groupByRegion(readHolders(DATA_PATH)),
      credentials: { total: creds.length, active: creds.filter(c => !c.revoked).length, revoked: creds.filter(c => c.revoked).length },
    });
  });

  return router;
}
