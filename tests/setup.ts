import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
// Runs before each test file's imports. Never use developer credentials or data.
const dir = mkdtempSync(join(tmpdir(), 'vericred-test-'));
process.env.DATA_DIR = dir;
process.env.ADMIN_API_KEY = randomBytes(32).toString('hex');
process.env.PSEUDO_SECRET = randomBytes(32).toString('hex');
process.env.NODE_ENV = 'test';
delete process.env.ISSUER_URL;
delete process.env.DEMO_MODE;
delete process.env.PII_ADMIN_MODE;
writeFileSync(join(dir, 'holders.json'), JSON.stringify([{ id: 'test-holder', firstName: 'Test', lastName: 'Person', email: 'test@example.org', dateOfBirth: '2000-01-01', region: 'Graz', defaultPassword: 'must-not-leak', customPassword: 'must-not-leak' }]));

for (const name of ['EUDI_ISSUER_REGISTRAR_DATASET_PATH', 'EUDI_VERIFIER_REGISTRAR_DATASET_PATH', 'WALLET_PROFILE', 'EUDI_ISSUER_CERT_CHAIN_PATH', 'EUDI_VERIFIER_CERT_CHAIN_PATH', 'EUDI_VERIFIER_KEY_PATH', 'TRUSTED_PROXY_CIDRS', 'EUDI_REGISTRATION_POLICY', 'EUDI_WALLET_ATTESTATION_POLICY_PATH', 'EUDI_ISSUER_REGISTRATION_CERT_PATH', 'EUDI_VERIFIER_REGISTRATION_CERT_PATH']) delete process.env[name];
