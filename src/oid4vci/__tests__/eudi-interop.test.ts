/** Simulated wallet protocol regression. This is not an independent EUDI reference-wallet certification. */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import type { Server } from 'node:http';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, calculateJwkThumbprint, importJWK, type JWK } from 'jose';
import { createHash } from 'node:crypto';
import { getIssuerKeyPair } from '../../keys/manager.js';
import { loadConfig } from '../../config/loader.js';
import { decodeDisclosure } from '../../sdjwt/disclosures.js';
import { createOfferRouter } from '../offer.js';
import { createTokenRouter } from '../token.js';
import { createCredentialRouter } from '../issuer.js';
import { createOid4vpRouter } from '../../oid4vp/router.js';

const sha256 = (text: string) => createHash('sha256').update(text, 'ascii').digest('base64url');

describe('OpenID4VCI/VP 1.0 custom-profile wallet simulation issuance and selective presentation', () => {
  let server: Server;
  let serverUrl: string;
  const post = (path: string, body: unknown, bearer?: string) => fetch(serverUrl + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(bearer ? { Authorization: 'Bearer ' + bearer } : {}) },
    body: JSON.stringify(body),
  });
  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    // Independent-wallet and live-database acceptance remain separate gates.
    const dob = (new Date().getUTCFullYear() - 19) + '-01-01';
    app.use(createOfferRouter(id => id === 'eudi-holder-01' ? { id, dateOfBirth: dob } : null));
    app.use(createTokenRouter());
    app.use(createCredentialRouter('interop-test-pseudonym-secret'));
    app.use(createOid4vpRouter());
    server = await new Promise<Server>(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Expected TCP listener');
    serverUrl = 'http://127.0.0.1:' + address.port;
  });
  afterAll(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));

  it('issues via offer and proof, verifies signature commitments, and presents only age_over_18', async () => {
    const config = loadConfig();
    const holderKeys = await generateKeyPair('ES256');
    const holderJwk = await exportJWK(holderKeys.publicKey);
    const offerResponse = await post('/offer', { holderId: 'eudi-holder-01', credentialType: 'AgeCredential' });
    expect(offerResponse.status).toBe(200);
    const { offer } = await offerResponse.json() as any;
    expect(offer.credential_configuration_ids).toEqual(['AgeCredential']);
    const tokenRequest = {
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'],
    };
    const tokenResponse = await post('/token', tokenRequest);
    expect(tokenResponse.status).toBe(200);
    const token = await tokenResponse.json() as any;
    expect((await post('/token', tokenRequest)).status).toBe(400);
    const nonce = await (await post('/nonce', {})).json() as any;
    const proofJwt = await new SignJWT({ nonce: nonce.c_nonce }).setAudience(config.issuer.url).setIssuedAt()
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: holderJwk }).sign(holderKeys.privateKey);
    const credentialResponse = await post('/credentials', {
      credential_configuration_id: 'AgeCredential', proofs: { jwt: [proofJwt] },
    }, token.access_token);
    expect(credentialResponse.status).toBe(200);
    const issued = await credentialResponse.json() as any;
    expect(issued.credentials).toHaveLength(1);
    const [issuerJwt, ...disclosures] = (issued.credentials[0].credential as string).split('~');
    expect(disclosures.pop()).toBe('');
    const { publicKey: issuerPublicKey } = await getIssuerKeyPair();
    const { payload, protectedHeader } = await jwtVerify(issuerJwt, issuerPublicKey, {
      algorithms: ['ES256'], issuer: config.issuer.did, requiredClaims: ['iat', 'exp', 'cnf', '_sd', 'vct'],
    });
    expect(protectedHeader.typ).toBe('dc+sd-jwt');
    expect(payload.vct).toBe('urn:vericred:credential:AgeCredential:1');
    expect(payload._sd_alg).toBe('sha-256');
    expect(payload.cnf).toEqual({ jwk: holderJwk });
    expect((payload.cnf as { jwk: JWK }).jwk.d).toBeUndefined();
    const status = payload.credentialStatus as any;
    expect(status).toMatchObject({ type: 'StatusList2021Entry', statusPurpose: 'revocation', statusListIndex: '0' });
    expect(status.statusListCredential).toMatch(/\/status\/[^/]+$/);
    const commitments = payload._sd as string[];
    expect(commitments).toHaveLength(disclosures.length);
    const byName: Record<string, string> = {};
    const claims: Record<string, unknown> = {};
    for (const encoded of disclosures) {
      const [, name, value] = decodeDisclosure(encoded);
      byName[name] = encoded;
      claims[name] = value;
      expect(commitments).toContain(sha256(encoded));
    }
    expect(claims).toMatchObject({ age_over_18: true, age_over_21: false });
    expect(claims.dateOfBirth).toBeUndefined();
    const initResponse = await post('/api/oid4vp/initiate', { credentialType: 'AgeCredential' });
    expect(initResponse.status).toBe(200);
    const session = await initResponse.json() as any;
    const params = new URL(session.requestUri).searchParams;
    expect(params.has('request_uri')).toBe(false);
    const request = Object.fromEntries(params) as any;
    expect(request.client_id).toBe('redirect_uri:' + request.response_uri);
    expect(JSON.parse(request.dcql_query).credentials[0]).toMatchObject({
      id: 'credential', meta: { vct_values: ['urn:vericred:credential:AgeCredential:1'] },
      claims: [{ path: ['age_over_18'], values: [true] }],
    });
    // SD-JWT+KB is SD-JWT (including its trailing '~') directly followed by KB-JWT.
    const presentedSdJwt = issuerJwt + '~' + byName.age_over_18 + '~';
    const kbJwt = await new SignJWT({ nonce: request.nonce, sd_hash: sha256(presentedSdJwt) })
      .setAudience(request.client_id).setIssuedAt().setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' }).sign(holderKeys.privateKey);
    const presentation = presentedSdJwt + kbJwt;
    // Verify with the public key embedded in the credential, not a separate test-only holder key lookup.
    const cnf = payload.cnf as { jwk: JWK };
    expect(await calculateJwkThumbprint(cnf.jwk)).toBe(await calculateJwkThumbprint(holderJwk));
    const holderPublicKey = await importJWK(cnf.jwk, 'ES256');
    const { payload: binding } = await jwtVerify(kbJwt, holderPublicKey, {
      algorithms: ['ES256'], typ: 'kb+jwt', audience: request.client_id, maxTokenAge: 300,
    });
    expect(binding.nonce).toBe(request.nonce);
    expect(binding.sd_hash).toBe(sha256(presentedSdJwt));
    const result = await post('/api/oid4vp/response/' + session.sessionId, { state: session.sessionId, vp_token: { credential: [presentation] } });
    expect(result.status).toBe(200);
    const sessionResponse = await fetch(serverUrl + '/api/oid4vp/session/' + session.sessionId, {
      headers: { Authorization: 'Bearer ' + session.readToken },
    });
    expect(await sessionResponse.json()).toEqual({ status: 'verified', claims: { age_over_18: true } });
    expect(presentation).not.toContain(byName.age_over_21);
    expect(presentation).not.toContain(byName.age_attested_at);
    expect(commitments).not.toContain(sha256(Buffer.from(JSON.stringify(['guessed-salt', 'age_over_21', false])).toString('base64url')));
  });
});
