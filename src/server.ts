import express from 'express';
import { randomBytes } from 'crypto';
import { loadConfig } from './config/loader.js';
import { getIssuerKeyPair } from './keys/manager.js';
import { createDidRouter } from './did/publisher.js';
import { createMetadataRouter } from './oid4vci/metadata.js';
import { createTokenRouter } from './oid4vci/token.js';
import { createCredentialRouter } from './oid4vci/issuer.js';
import { createOfferRouter } from './oid4vci/offer.js';
import { loadJsonConnector } from './connectors/json.js';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const config = loadConfig();
const pseudonymSecret = randomBytes(32).toString('hex'); // In Sprint 2: persist this

// Data connector
const lookup = loadJsonConnector(config.dataSource.path ?? './data/holders.json');

// Routes
app.use(createDidRouter());
app.use(createMetadataRouter());
app.use(createTokenRouter());
app.use(createCredentialRouter(pseudonymSecret));
app.use(createOfferRouter(lookup));

// Health check
app.get('/health', (_req, res) => res.json({ status: 'ok', issuer: config.issuer.did }));

const PORT = process.env.PORT ?? 3100;

// Pre-warm keypair on startup
await getIssuerKeyPair();

app.listen(PORT, () => {
  console.log(`\n🎫 VeriCred issuer running at ${config.issuer.url}`);
  console.log(`   DID document: ${config.issuer.url}/.well-known/did.json`);
  console.log(`   OID4VCI metadata: ${config.issuer.url}/.well-known/openid-credential-issuer`);
  console.log(`   Create offer: POST ${config.issuer.url}/offer { "identifier": "alice@example.com" }\n`);
});
