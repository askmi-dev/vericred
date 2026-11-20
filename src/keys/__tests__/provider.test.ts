import { describe, it, expect, afterEach } from 'vitest';
import { generateKeyPairSync, sign as nodeSign } from 'crypto';
import { jwtVerify, importJWK, exportJWK, calculateJwkThumbprint } from 'jose';
import type { JWK } from 'jose';
import { getKeyProvider, setKeyProvider, signCompactJws } from '../provider.js';
import type { IssuerKeyProvider } from '../provider.js';

/**
 * A provider whose private key is never handed to VeriCred: it only exposes a raw
 * sign() function, like a KMS/HSM client would.
 */
function makeExternalProvider(): IssuerKeyProvider & { signCalls: number } {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const publicJwk = publicKey.export({ format: 'jwk' }) as JWK;
  let signCalls = 0;
  const active = { kid: 'external-kid-1', publicKey: publicJwk };
  return {
    get signCalls() {
      return signCalls;
    },
    async getActiveKey() {
      return active;
    },
    async getAllPublicKeys() {
      return [active];
    },
    async signJwt(payload, typ) {
      return signCompactJws({ alg: 'ES256', kid: active.kid, typ }, payload, async (input) => {
        signCalls++;
        return new Uint8Array(nodeSign('sha256', input, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
      });
    },
    async rotate() {
      return active;
    },
  };
}

describe('IssuerKeyProvider', () => {
  const savedEnv = process.env['KEY_PROVIDER'];
  afterEach(() => {
    setKeyProvider(null);
    if (savedEnv === undefined) delete process.env['KEY_PROVIDER'];
    else process.env['KEY_PROVIDER'] = savedEnv;
  });

  it('signs through a registered external provider and the JWT verifies with its public key', async () => {
    const external = makeExternalProvider();
    setKeyProvider(external);

    const jwt = await getKeyProvider().signJwt({ iss: 'did:web:example', iat: 1 }, 'vc+sd-jwt');
    const { publicKey, kid } = await getKeyProvider().getActiveKey();
    const { payload, protectedHeader } = await jwtVerify(jwt, await importJWK(publicKey, 'ES256'));

    expect(external.signCalls).toBe(1);
    expect(protectedHeader).toEqual({ alg: 'ES256', kid, typ: 'vc+sd-jwt' });
    expect(payload['iss']).toBe('did:web:example');
  });

  it('rejects a signature that is not 64 bytes (r||s)', async () => {
    await expect(
      signCompactJws({ alg: 'ES256', kid: 'k', typ: 'JWT' }, {}, async () => new Uint8Array(70))
    ).rejects.toThrow(/64 bytes/);
  });

  it('a JWT signed by one provider does not verify under another provider key', async () => {
    const a = makeExternalProvider();
    const b = makeExternalProvider();
    const jwt = await a.signJwt({ x: 1 }, 'JWT');
    const bKey = await importJWK((await b.getActiveKey()).publicKey, 'ES256');
    await expect(jwtVerify(jwt, bKey)).rejects.toThrow();
  });

  it('fails closed on an unknown KEY_PROVIDER when no adapter is registered', () => {
    process.env['KEY_PROVIDER'] = 'aws-kms';
    expect(() => getKeyProvider()).toThrow(/Unknown KEY_PROVIDER "aws-kms"/);
  });

  it('a registered adapter takes precedence over KEY_PROVIDER', async () => {
    process.env['KEY_PROVIDER'] = 'aws-kms';
    const external = makeExternalProvider();
    setKeyProvider(external);
    expect(getKeyProvider()).toBe(external);
    const jwk = (await getKeyProvider().getActiveKey()).publicKey;
    expect(await calculateJwkThumbprint(jwk, 'sha256')).toBeTruthy();
    expect(await exportJWK(await importJWK(jwk, 'ES256'))).toBeTruthy();
  });
});
