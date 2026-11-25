import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest';
import { readFileSync, existsSync, rmSync, mkdirSync } from 'fs';
import { createPrivateKey, createPublicKey, generateKeyPairSync, X509Certificate } from 'crypto';
import { decodeProtectedHeader, jwtVerify } from 'jose';
import { join } from 'path';
import type { VeriCredConfig } from '../../config/types.js';
import { hasOpenssl, generateX5cFixtures } from './x5c-fixtures.js';

// Test-only chain (root -> intermediate -> leaf) generated at test time by
// x5c-fixtures.ts, so no private key lives in the repository. Without openssl
// the suite is skipped locally; on Linux CI a missing openssl fails loudly.
if (!hasOpenssl && process.env.CI && process.platform === 'linux') {
  throw new Error('x5c tests need openssl on the PATH in CI');
}
const FIX = hasOpenssl ? generateX5cFixtures() : '';
afterAll(() => { if (FIX) rmSync(FIX, { recursive: true, force: true }); });
const suite = hasOpenssl ? describe : describe.skip;
const pem = (f: string) => readFileSync(join(FIX, f), 'utf-8');
const leafPrivate = hasOpenssl ? createPrivateKey(pem('leaf.key')) : (undefined as never);
const leafPublic = hasOpenssl ? createPublicKey(leafPrivate) : (undefined as never);
const ISSUER_URL = 'https://issuer.example.test';
const CHAIN_PATH = join(FIX, 'chain.pem');

// Signing goes through the key provider; its default (file) provider is backed
// by the test leaf key so x5c validation and signatures use the certificate key.
vi.mock('../manager.js', async () => {
  const { SignJWT, exportJWK } = await import('jose');
  const getIssuerKeyPair = async () => ({ privateKey: leafPrivate, publicKey: leafPublic, kid: 'leaf-kid' });
  return {
    getIssuerKeyPair,
    fileKeyProvider: {
      async getActiveKey() { return { kid: 'leaf-kid', publicKey: await exportJWK(leafPublic) }; },
      async getAllPublicKeys() { return [{ kid: 'leaf-kid', publicKey: await exportJWK(leafPublic) }]; },
      async signJwt(payload: Record<string, unknown>, { typ, x5c }: { typ: string; x5c?: string[] }) {
        return new SignJWT(payload)
          .setProtectedHeader({ alg: 'ES256', kid: 'leaf-kid', typ, ...(x5c ? { x5c } : {}) })
          .sign(leafPrivate);
      },
      async rotate() { throw new Error('not used in this test'); },
    },
  };
});

const config = (certificateChain?: string): VeriCredConfig => ({
  issuer: { name: 'Test', url: ISSUER_URL, did: 'did:web:issuer.example.test', certificateChain },
  credential: { type: 'T', expiresInDays: 30 },
  dataSource: { type: 'manual' },
  fieldMappings: {},
});
vi.mock('../../config/loader.js', () => ({ loadConfig: () => mockedConfig }));
let mockedConfig: VeriCredConfig;

const { parseCertificateChain, validateCertificateChain, getIssuerSigningIdentity } = await import('../x5c.js');
const { buildStatusListJWT, assignStatusIndex } = await import('../../revocation/statuslist.js');

const chain = () => parseCertificateChain(pem('chain.pem'));
const [leaf, intermediate] = (hasOpenssl ? chain() : []) as [X509Certificate, X509Certificate];
const root = hasOpenssl ? new X509Certificate(pem('root.pem')) : (undefined as never);

suite('x5c certificate chain', () => {
  it('returns standard-Base64 DER, leaf first, root excluded', () => {
    const x5c = validateCertificateChain(chain(), leafPublic, ISSUER_URL);
    expect(x5c).toHaveLength(2);
    expect(x5c[0]).toBe(leaf.raw.toString('base64'));
    expect(x5c[1]).toBe(intermediate.raw.toString('base64'));
    expect(x5c.join('')).not.toMatch(/[-_]/); // not base64url
  });

  it('accepts the URL with a trailing slash, or a path under the DNS SAN host', () => {
    expect(() => validateCertificateChain(chain(), leafPublic, ISSUER_URL + '/')).not.toThrow();
    expect(() => validateCertificateChain(chain(), leafPublic, ISSUER_URL + '/tenant-a')).not.toThrow();
  });

  it('refuses a certificate that does not certify the issuer key', () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey;
    expect(() => validateCertificateChain(chain(), other, ISSUER_URL)).toThrow(/does not certify the current issuer key/);
  });

  it('refuses a chain that includes the root trust anchor', () => {
    expect(() => validateCertificateChain([leaf, intermediate, root], leafPublic, ISSUER_URL)).toThrow(/self-signed/);
  });

  it('refuses a chain out of order', () => {
    expect(() => validateCertificateChain([leaf, root], leafPublic, ISSUER_URL)).toThrow(/self-signed|not issued by/);
    expect(() => validateCertificateChain([leaf, leaf], leafPublic, ISSUER_URL)).toThrow(/not issued by/);
  });

  it('refuses an expired chain', () => {
    expect(() => validateCertificateChain(chain(), leafPublic, ISSUER_URL, new Date('2200-01-01'))).toThrow(/not valid now/);
  });

  it('refuses an issuer URL the certificate does not name', () => {
    expect(() => validateCertificateChain(chain(), leafPublic, 'https://other.example')).toThrow(/subjectAltName/);
  });

  it('keeps did:web and no x5c when no chain is configured', async () => {
    expect(await getIssuerSigningIdentity(config())).toEqual({ iss: 'did:web:issuer.example.test' });
  });

  it('switches iss to the issuer URL when a chain is configured', async () => {
    const id = await getIssuerSigningIdentity(config(CHAIN_PATH));
    expect(id.iss).toBe(ISSUER_URL);
    expect(id.x5c).toHaveLength(2);
  });
});

suite('Status List Token with x5c', () => {
  const DATA_DIR = './data-test-x5c';
  beforeEach(() => {
    process.env['DATA_DIR'] = DATA_DIR;
    if (existsSync(DATA_DIR)) rmSync(DATA_DIR, { recursive: true, force: true });
    mkdirSync(DATA_DIR, { recursive: true });
  });
  afterEach(() => { if (existsSync(DATA_DIR)) rmSync(DATA_DIR, { recursive: true, force: true }); });

  it('carries the chain, and verifies with the leaf certificate key', async () => {
    mockedConfig = config(CHAIN_PATH);
    assignStatusIndex('vc1', 'a@example.com');
    const jwt = await buildStatusListJWT();
    const header = decodeProtectedHeader(jwt);
    expect(header.typ).toBe('statuslist+jwt');
    expect(header.x5c).toEqual([leaf.raw.toString('base64'), intermediate.raw.toString('base64')]);

    // What a wallet does: take the key from x5c[0], not from a DID.
    const fromHeader = new X509Certificate(Buffer.from(header.x5c![0]!, 'base64')).publicKey;
    const { payload } = await jwtVerify(jwt, fromHeader);
    expect(payload.iss).toBe(ISSUER_URL);
  });

  it('refuses to sign when the chain is invalid, so /status fails closed', async () => {
    mockedConfig = config(CHAIN_PATH);
    mockedConfig.issuer.url = 'https://other.example';
    assignStatusIndex('vc1', 'a@example.com');
    await expect(buildStatusListJWT()).rejects.toThrow(/subjectAltName/);
  });
});
