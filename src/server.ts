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

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const config = loadConfig();
const secrets = loadSecrets();
const dataPath = config.dataSource.path ?? './data/holders.json';

// Startup: spawn synthetic holders, log session
markProcessStart();
const sessionId = logStartup(5);
generateHolders(5, secrets.pseudonymSecret, sessionId, dataPath);

// Data connector (reads holders.json)
const lookup = buildConnector(config);

// ── Public routes (wallet-facing) ──────────────────────────
app.use(createDidRouter());
app.use(createMetadataRouter());
app.use(createTokenRouter());
app.use(createCredentialRouter(secrets.pseudonymSecret));

// ── Protected routes (admin only) ──────────────────────────
app.use('/offer', requireAdmin);  // offer generation is admin-only
app.use(createOfferRouter(lookup));
app.use(createRevocationRouter());
app.use(createAdminRouter());

// Health (public, no PII)
app.get('/health', (_req, res) => res.json({ status: 'ok', issuer: config.issuer.did }));

const PORT = process.env.PORT ?? 3100;
export const SERVER_STARTED_AT = new Date();

await getIssuerKeyPair();

app.listen(PORT, () => {
  console.log(`\n🎫 VeriCred running at ${config.issuer.url}`);
  console.log(`   Admin:    ${config.issuer.url}/admin`);
  console.log(`   DID:      ${config.issuer.url}/.well-known/did.json`);
  console.log(`   Metadata: ${config.issuer.url}/.well-known/openid-credential-issuer\n`);
});
