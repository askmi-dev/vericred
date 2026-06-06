import express from 'express';
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
  process.loadEnvFile();
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

  const isUnconfigured = config.issuer.name === 'VeriCred Issuer' || config.issuer.url.includes('localhost');

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

// Console routes (Admin only)
app.use('/console', requireAdmin);

app.get('/console', (_req, res) => {
  res.redirect('/console/dashboard');
});

app.get('/console/:page(dashboard|schema|monitor|logo|security|legacy/blockchain|setup)', (req, res) => {
  const page = req.params.page;
  
  // Check if setup is needed
  if (page !== 'setup') {
    const config = loadConfig();
    if (config.issuer.name === 'VeriCred Issuer' || config.issuer.url.includes('localhost')) {
      res.redirect('/console/setup');
      return;
    }
  }

  res.sendFile(path.resolve(`stitch-out/dist/console/${page}/index.html`));
});

app.get('/console/:page(dashboard|schema|monitor|logo|legacy/blockchain|setup)/index.html', (req, res) => {
  const page = req.params.page;
  
  if (page !== 'setup') {
    const config = loadConfig();
    if (config.issuer.name === 'VeriCred Issuer' || config.issuer.url.includes('localhost')) {
      res.redirect('/console/setup');
      return;
    }
  }

  res.sendFile(path.resolve(`stitch-out/dist/console/${page}/index.html`));
});

// Dev routes (Development only)
if (process.env['NODE_ENV'] === 'development') {
  app.get('/dev', (_req, res) => {
    res.redirect('/dev/navigator');
  });
  app.get('/dev/navigator', (_req, res) => {
    res.sendFile(path.resolve('stitch-out/dist/dev/navigator/index.html'));
  });
  app.get('/dev/navigator/index.html', (_req, res) => {
    res.sendFile(path.resolve('stitch-out/dist/dev/navigator/index.html'));
  });
} else {
  app.use('/dev', (_req, res) => {
    res.status(404).send('Not Found');
  });
}

// Protected routes (admin only)
app.use('/offer', requireAdmin);
app.use(createOfferRouter(lookup));
app.use(createRevocationRouter());
app.use(createAdminRouter(connector));

// Public static files fallback (serves index.html at root, assets under /assets, favicon, etc.)
app.use(express.static(path.resolve('stitch-out/dist')));

// Health (public, no PII)
app.get('/health', (_req, res) => res.json({ status: 'ok', issuer: config.issuer.did }));

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
