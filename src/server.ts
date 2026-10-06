import express from 'express';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { loadConfig } from './config/loader.js';
import { loadSecrets } from './config/secrets.js';
import { getIssuerKeyPair } from './keys/manager.js';
import { createDidRouter } from './did/publisher.js';
import { createMetadataRouter } from './oid4vci/metadata.js';
import { createTokenRouter } from './oid4vci/token.js';
import { createCredentialRouter } from './oid4vci/issuer.js';
import { createOfferRouter } from './oid4vci/offer.js';
import { createAdminRouter } from './admin/router.js';
import { createRevocationRouter } from './revocation/router.js';
import { createOid4vpRouter } from './oid4vp/router.js';
import { createConsentRouter } from './oid4vci/consent.js';
import { requireAdmin } from './middleware/auth.js';
import { generateHolders } from './connectors/generator.js';
import { logStartup, markProcessStart } from './admin/runtime.js';
import { buildConnector } from './connectors/index.js';
import { getTemplate, listTemplates } from './credentials/registry.js';

// Register all built-in templates (side-effect imports)
import './credentials/templates/age.js';
import './credentials/templates/employee.js';
import './credentials/templates/membership.js';

try {
  const explicitEnv = { ...process.env };
  process.loadEnvFile();
  for (const [key, value] of Object.entries(explicitEnv)) {
    if (value !== undefined) process.env[key] = value;
  }
} catch {
  // Ignore error if .env file is missing
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const config = loadConfig();
const secrets = loadSecrets();
const dataPath = config.dataSource.path ?? './data/holders.json';

// --- Startup: fail-fast template validation ---
{
  let startupOk = true;
  console.log('[startup] Validating credential template config...');

  // 1. Check configured type exists
  let template;
  try {
    template = getTemplate(config.credential.type);
  } catch (e) {
    console.error('[startup] FATAL: ' + (e as Error).message);
    console.error('[startup] Available types: ' + listTemplates().map(t => t.id).join(', '));
    startupOk = false;
  }

  if (template) {
    // 2. Check field mappings cover required fields
    const mappingErrors = template.validateMappings(config.fieldMappings);
    if (mappingErrors.length > 0) {
      console.error('[startup] FATAL: Field mapping errors for ' + config.credential.type + ':');
      for (const err of mappingErrors) console.error('  - ' + err);
      startupOk = false;
    }

    // 3. Check templateOptions (if template supports it)
    if (template.validateOptions) {
      const optErrors = template.validateOptions(config.templateOptions ?? {});
      if (optErrors.length > 0) {
        console.error('[startup] FATAL: templateOptions errors for ' + config.credential.type + ':');
        for (const err of optErrors) console.error('  - ' + err);
        startupOk = false;
      }
    }

    if (startupOk) {
      console.log('[startup] Template "' + config.credential.type + '" OK');
    }
  }

  const isUnconfigured = config.issuer.name === 'VeriCred Issuer' && config.issuer.did.includes('localhost');

  if (!startupOk && !isUnconfigured) {
    console.error('[startup] Configuration errors found. Refusing to start.');
    process.exit(1);
  } else if (!startupOk && isUnconfigured) {
    console.warn('[startup] WARNING: Gateway is unconfigured. Redirecting to setup wizard.');
  }
}

// Startup
markProcessStart();
const sessionId = logStartup(5);

// Synthetic holders only in DEMO_MODE - never in production
if (process.env['DEMO_MODE'] === 'true') {
  generateHolders(5, secrets.pseudonymSecret, sessionId, dataPath);
  console.log('  [DEMO_MODE] Synthetic holders generated. Set DEMO_MODE=false for production.');
} else {
  console.log('  [INFO] DEMO_MODE not set - no synthetic holders generated.');
}

// Data connector
const connector = buildConnector(config);
const lookup = (id: string) => connector.lookup(id);

// Public routes (wallet-facing)
app.use(createDidRouter());
app.use(createMetadataRouter());
app.use(createTokenRouter());
app.use(createCredentialRouter(secrets.pseudonymSecret));
app.use(createOid4vpRouter());

// Public, unauthenticated consent surface (GET .../claims, POST .../decide,
// and the page shell below) -- rate-limited since there's no auth gate.
app.use('/consent', rateLimit({ windowMs: 15 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false }));
app.use(createConsentRouter());

// :id is constrained to the exact format createConsentRecord generates
// (32 hex chars); it is never read below -- the file served is a static
// SPA shell regardless of :id -- but the constraint rejects malformed ids
// with a plain 404 up front instead of reaching sendFile at all. The
// filename passed to sendFile is a literal, resolved against the `root`
// option rather than path.join'd by hand, so it can't escape distPath.
//
// CodeQL (js/path-injection) still flags the line below. It isn't :id --
// it's FRONTEND_DIST_PATH, which CodeQL's env-var source heuristic treats
// as "user-provided." Here it's deploy-time server config (same value this
// file already resolves the identical way for /console, /dev/navigator,
// and the static fallback, none of which are new lines in this diff and
// so aren't flagged) -- never derived from a request. Confirmed by testing:
// switching from path.join to sendFile's documented-safe `root` option
// didn't change the finding, which only makes sense if distPath itself,
// not :id, is what's being traced.
app.get('/consent/:id([0-9a-f]{32})', (_req, res) => {
  const distPath = process.env.FRONTEND_DIST_PATH || 'stitch-out/dist';
  res.sendFile('consent/index.html', { root: path.resolve(distPath) }); // lgtm[js/path-injection]
});

// Console routes (Admin only)
app.use('/console', requireAdmin);

app.get('/console', (_req, res) => {
  res.redirect('/console/dashboard');
});

app.get('/console/:page(dashboard|holders|schema|monitor|logo|security|setup|revoke)', (req, res) => {
  const page = req.params.page;
  const distPath = process.env.FRONTEND_DIST_PATH || 'stitch-out/dist';

  // Check if setup is needed
  if (page !== 'setup') {
    const config = loadConfig();
    const isUnconfigured = config.issuer.name === 'VeriCred Issuer' && config.issuer.did.includes('localhost');
    if (isUnconfigured) {
      res.redirect('/console/setup');
      return;
    }
  }

  res.sendFile(path.resolve(path.join(distPath, `console/${page}/index.html`)));
});

app.get('/console/:page(dashboard|holders|schema|monitor|logo|security|setup|revoke)/index.html', (req, res) => {
  const page = req.params.page;
  const distPath = process.env.FRONTEND_DIST_PATH || 'stitch-out/dist';

  if (page !== 'setup') {
    const config = loadConfig();
    const isUnconfigured = config.issuer.name === 'VeriCred Issuer' && config.issuer.did.includes('localhost');
    if (isUnconfigured) {
      res.redirect('/console/setup');
      return;
    }
  }

  res.sendFile(path.resolve(path.join(distPath, `console/${page}/index.html`)));
});

// Dev routes (Development only)
if (process.env['NODE_ENV'] === 'development') {
  const distPath = process.env.FRONTEND_DIST_PATH || 'stitch-out/dist';
  app.get('/dev', (_req, res) => {
    res.redirect('/dev/navigator');
  });
  app.get('/dev/navigator', (_req, res) => {
    res.sendFile(path.resolve(path.join(distPath, 'dev/navigator/index.html')));
  });
  app.get('/dev/navigator/index.html', (_req, res) => {
    res.sendFile(path.resolve(path.join(distPath, 'dev/navigator/index.html')));
  });
} else {
  app.use('/dev', (_req, res) => {
    res.status(404).send('Not Found');
  });
}

// Protected routes (admin only)
app.use('/offer', rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false }));
app.use('/offer', requireAdmin);
app.use(createOfferRouter(lookup));
app.use(createRevocationRouter());
app.use(createAdminRouter(connector));

// Public static files fallback
const distPath = process.env.FRONTEND_DIST_PATH || 'stitch-out/dist';
app.use(express.static(path.resolve(distPath)));

// Health (public, no PII)
app.get('/health', (_req, res) => res.json({ status: 'ok', issuer: config.issuer.did }));

// Public Info (for white-label landing page)
app.get('/api/info', (_req, res) => {
  const cfg = loadConfig();
  const isConfigured = cfg.issuer.name !== 'VeriCred Issuer' && !cfg.issuer.did.includes('localhost');
  res.json({
    issuerName: cfg.issuer.name,
    issuerDid: cfg.issuer.did,
    isConfigured,
    supportedTemplates: listTemplates().map(t => ({ id: t.id, name: t.id.replace('Credential', '') }))
  });
});

const PORT = process.env['PORT'] ?? 3100;
export const SERVER_STARTED_AT = new Date();

await getIssuerKeyPair();

app.listen(PORT, () => {
  console.log('');
  console.log('VeriCred running at ' + config.issuer.url);
  console.log('  Admin:    ' + config.issuer.url + '/admin');
  console.log('  DID:      ' + config.issuer.url + '/.well-known/did.json');
  console.log('  Metadata: ' + config.issuer.url + '/.well-known/openid-credential-issuer');
  console.log('');
});
