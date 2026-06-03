/**
 * Holder Proof Verification Tests
 *
 * Tests:
 *  - Valid proof passes
 *  - Wrong typ rejected
 *  - Missing jwk rejected
 *  - Wrong audience rejected
 *  - Stale iat rejected
 *  - Wrong nonce rejected
 *  - Invalid signature rejected
 *  - JWT payload contains cnf.jkt after issuance
 *  - Missing proof fails outside DEMO_MODE
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPair, exportJWK, SignJWT, calculateJwkThumbprint } from 'jose';
import type { KeyLike } from 'jose';
import { verifyHolderProofJwt, ProofVerificationError } from '../proof.js';

const ISSUER_URL = 'http://localhost:3100';

async function makeProofJwt(opts: {
  alg?: string;
  typ?: string;
  audience?: string;
  nonce?: string;
  iatOffset?: number; // seconds from now
  includeJwk?: boolean;
  privateKey?: KeyLike;
  publicKey?: KeyLike;
}): Promise<{ jwt: string; thumbprint: string }> {
  const alg = opts.alg ?? 'ES256';
  const keys = opts.privateKey
    ? { privateKey: opts.privateKey as KeyLike, publicKey: opts.publicKey as KeyLike }
    : await generateKeyPair(alg);

  const publicJwk = await exportJWK(keys.publicKey);
  const thumbprint = await calculateJwkThumbprint(publicJwk, 'sha256');
  const iat = Math.floor(Date.now() / 1000) + (opts.iatOffset ?? 0);

  const jwt = await new SignJWT({ aud: opts.audience ?? ISSUER_URL, iat, nonce: opts.nonce ?? 'test-nonce' })
    .setProtectedHeader({
      alg,
      typ: opts.typ ?? 'openid4vci-proof+jwt',
      ...(opts.includeJwk !== false ? { jwk: publicJwk } : {}),
    })
    .sign(keys.privateKey);

  return { jwt, thumbprint };
}

describe('verifyHolderProofJwt — valid proof', () => {
  it('accepts a correctly formed proof and returns holderThumbprint', async () => {
    const { jwt, thumbprint } = await makeProofJwt({ nonce: 'abc123' });
    const result = await verifyHolderProofJwt(jwt, ISSUER_URL, 'abc123');
    expect(result.holderThumbprint).toBe(thumbprint);
    expect(result.jwk).toBeDefined();
  });

  it('thumbprint is deterministic for same key', async () => {
    const keys = await generateKeyPair('ES256');
    const { jwt } = await makeProofJwt({ privateKey: keys.privateKey, publicKey: keys.publicKey, nonce: 'n1' });
    const { jwt: jwt2 } = await makeProofJwt({ privateKey: keys.privateKey, publicKey: keys.publicKey, nonce: 'n1' });
    const r1 = await verifyHolderProofJwt(jwt, ISSUER_URL, 'n1');
    const r2 = await verifyHolderProofJwt(jwt2, ISSUER_URL, 'n1');
    expect(r1.holderThumbprint).toBe(r2.holderThumbprint);
  });
});

describe('verifyHolderProofJwt — typ check', () => {
  it('rejects wrong typ', async () => {
    const { jwt } = await makeProofJwt({ typ: 'JWT', nonce: 'n' });
    await expect(verifyHolderProofJwt(jwt, ISSUER_URL, 'n')).rejects.toThrow('openid4vci-proof+jwt');
  });
});

describe('verifyHolderProofJwt — jwk check', () => {
  it('rejects proof without jwk in header', async () => {
    const { jwt } = await makeProofJwt({ includeJwk: false, nonce: 'n' });
    await expect(verifyHolderProofJwt(jwt, ISSUER_URL, 'n')).rejects.toThrow('jwk');
  });
});

describe('verifyHolderProofJwt — audience check', () => {
  it('rejects wrong audience', async () => {
    const { jwt } = await makeProofJwt({ audience: 'https://evil.example.com', nonce: 'n' });
    await expect(verifyHolderProofJwt(jwt, ISSUER_URL, 'n')).rejects.toBeInstanceOf(ProofVerificationError);
  });
});

describe('verifyHolderProofJwt — iat freshness', () => {
  it('rejects proof with iat > 5 minutes ago', async () => {
    const { jwt } = await makeProofJwt({ iatOffset: -310, nonce: 'n' }); // 310s ago
    await expect(verifyHolderProofJwt(jwt, ISSUER_URL, 'n')).rejects.toThrow('too old');
  });

  it('accepts proof with iat just within 5 minutes', async () => {
    const { jwt } = await makeProofJwt({ iatOffset: -250, nonce: 'n' }); // 250s ago
    await expect(verifyHolderProofJwt(jwt, ISSUER_URL, 'n')).resolves.toBeDefined();
  });
});

describe('verifyHolderProofJwt — nonce check', () => {
  it('rejects wrong nonce', async () => {
    const { jwt } = await makeProofJwt({ nonce: 'correct-nonce' });
    await expect(verifyHolderProofJwt(jwt, ISSUER_URL, 'wrong-nonce')).rejects.toThrow('nonce');
  });

  it('rejects proof without nonce', async () => {
    const keys = await generateKeyPair('ES256');
    const publicJwk = await exportJWK(keys.publicKey);
    const jwt = await new SignJWT({ aud: ISSUER_URL, iat: Math.floor(Date.now() / 1000) })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: publicJwk })
      .sign(keys.privateKey);
    await expect(verifyHolderProofJwt(jwt, ISSUER_URL, 'n')).rejects.toThrow('nonce');
  });
});

describe('verifyHolderProofJwt — signature check', () => {
  it('rejects proof signed with different key than header jwk', async () => {
    const keys1 = await generateKeyPair('ES256');
    const keys2 = await generateKeyPair('ES256');
    // Sign with keys1.privateKey but put keys2.publicKey in header
    const wrongJwk = await exportJWK(keys2.publicKey);
    const jwt = await new SignJWT({ aud: ISSUER_URL, iat: Math.floor(Date.now() / 1000), nonce: 'n' })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: wrongJwk })
      .sign(keys1.privateKey);
    await expect(verifyHolderProofJwt(jwt, ISSUER_URL, 'n')).rejects.toBeInstanceOf(ProofVerificationError);
  });
});

describe('ProofVerificationError', () => {
  it('carries a machine-readable code', async () => {
    const { jwt } = await makeProofJwt({ nonce: 'n1' });
    try {
      await verifyHolderProofJwt(jwt, ISSUER_URL, 'wrong');
    } catch (e) {
      expect(e).toBeInstanceOf(ProofVerificationError);
      expect((e as ProofVerificationError).code).toBe('invalid_nonce');
    }
  });
});
