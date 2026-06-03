import express from 'express';
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

  // Check configured type exists
  let template;
  try {
    template = getTemplate(config.credential.type);
  } catch (e) {
    console.error('[startup] FATAL: ' + (e as Error).message);
    console.error('[startup] Available types: ' + listTemplates().map(t => t.id).join(', '));
    startupOk = false;
  }

  // Check field mappings cover required fields
  if (template) {
    const mappingErrors = template.validateMappings(config.fieldMappings);
    if (mappingErrors.length > 0) {
      console.error('[startup] FATAL: Field mapping errors for ' + config.credential.type + ':');
      for (const err of mappingErrors) console.error('  - ' + err);
      startupOk = false;
    } else {
      console.log('[startup] Template "' + config.credential.type + '" OK');
    }
  }

  if (!startupOk) {
    console.error('[startup] Configuration errors found. Refusing to start.');
    process.exit(1);
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
const lookup = buildConnector(config);

// Public routes (wallet-facing)
app.use(createDidRouter());
app.use(createMetadataRouter());
app.use(createTokenRouter());
app.use(createCredentialRouter(secrets.pseudonymSecret));

// Protected routes (admin only)
app.use('/offer', requireAdmin);
app.use(createOfferRouter(lookup));
app.use(createRevocationRouter());
app.use(createAdminRouter());

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
