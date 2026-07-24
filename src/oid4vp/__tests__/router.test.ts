import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import { readFileSync, existsSync } from 'fs';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createOid4vpRouter } from '../router.js';
import { getIssuerKeyPair } from '../../keys/manager.js';

const DATA_DIR = process.env.DATA_DIR ?? '.';
const SESSIONS_FILE = `${DATA_DIR}/oid4vp_sessions.json`;

describe('OID4VP Router Endpoints - Hardened Security Suite', () => {
  let app: express.Express;
  let server: any;
  let baseUrl: string;

  beforeAll(() => {
    app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(createOid4vpRouter());

    return new Promise<void>((resolve) => {
      server = app.listen(0, () => {
        const address = server.address();
        const port = typeof address === 'string' ? 0 : address.port;
        baseUrl = `http://localhost:${port}`;
        resolve();
      });
    });
  });

  afterAll(() => {
    return new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it('should initiate session and return session details and QR code', async () => {
    const res = await fetch(`${baseUrl}/api/oid4vp/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;

    expect(body.success).toBe(true);
    expect(body.sessionId).toBeDefined();
    expect(body.nonce).toBeDefined();
    expect(body.requestUri).toBeDefined();
    expect(body.qrCodeDataUrl).toContain('data:image/png;base64');
  });

  it('should return client metadata', async () => {
    const res = await fetch(`${baseUrl}/api/oid4vp/client-metadata`);
    expect(res.status).toBe(200);
    const body = await res.json() as any;

    expect(body.client_id).toContain('/api/oid4vp/client-metadata');
    expect(body.client_name).toBe('VeriCred Secure Verifier');
    expect(body.response_types_supported).toContain('vp_token');
    expect(body.vp_formats_supported['vc+sd-jwt']).toBeDefined();
  });

  it('should return 404 for non-existent session request-uri', async () => {
    const res = await fetch(`${baseUrl}/api/oid4vp/request/fake-session-id`);
    expect(res.status).toBe(404);
    const body = await res.json() as any;
    expect(body.error).toBe('session_not_found');
  });

  it('should get authorization request object for valid session', async () => {
    // 1. Initiate session
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const initBody = await initRes.json() as any;
    const sessionId = initBody.sessionId;

    // 2. Fetch request object
    const res = await fetch(`${baseUrl}/api/oid4vp/request/${sessionId}`);
    expect(res.status).toBe(200);
    const body = await res.json() as any;

    expect(body.client_id).toContain('/api/oid4vp/client-metadata');
    expect(body.response_uri).toContain(`/api/oid4vp/response/${sessionId}`);
    expect(body.response_mode).toBe('direct_post');
    expect(body.nonce).toBe(initBody.nonce);
    expect(body.presentation_definition).toBeDefined();
    expect(body.presentation_definition.input_descriptors[0].id).toBe('eu.europa.ec.eudiw.pid.1');
  });

  it('should accept direct_post response and parse selective disclosure vp_token', async () => {
    // 1. Initiate session
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const initBody = await initRes.json() as any;
    const sessionId = initBody.sessionId;

    // Create a mock SD-JWT disclosure block for "given_name" and "family_name"
    // Disclosures are array: [salt, name, value] base64url encoded
    const disclosure1 = Buffer.from(JSON.stringify(['salt1', 'given_name', 'Amelia'])).toString('base64url');
    const disclosure2 = Buffer.from(JSON.stringify(['salt2', 'family_name', 'S.'])).toString('base64url');
    const mockVpToken = `FAKE_JWT_HEADER.PAYLOAD.SIGNATURE~${disclosure1}~${disclosure2}~`;

    // 2. Submit post response
    const res = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        vp_token: mockVpToken,
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.success).toBe(true);
    expect(body.status).toBe('verified');

    // 3. Get session status to verify claims are parsed correctly
    const sessionRes = await fetch(`${baseUrl}/api/oid4vp/session/${sessionId}`);
    expect(sessionRes.status).toBe(200);
    const sessionBody = await sessionRes.json() as any;

    expect(sessionBody.status).toBe('verified');
    expect(sessionBody.claims.given_name).toBe('Amelia');
    expect(sessionBody.claims.family_name).toBe('S.');
  });

  it('should accept urlencoded direct_post response with mock bypass', async () => {
    // 1. Initiate session
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const initBody = await initRes.json() as any;
    const sessionId = initBody.sessionId;

    const disclosure = Buffer.from(JSON.stringify(['salt', 'given_name', 'Charlotte'])).toString('base64url');
    const mockVpToken = `FAKE_JWT~${disclosure}~`;

    // 2. Submit URL-encoded form data
    const formData = new URLSearchParams();
    formData.append('vp_token', mockVpToken);

    const res = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.success).toBe(true);

    // 3. Verify status
    const sessionRes = await fetch(`${baseUrl}/api/oid4vp/session/${sessionId}`);
    const sessionBody = await sessionRes.json() as any;
    expect(sessionBody.claims.given_name).toBe('Charlotte');
  });

  it('should fallback to mock/prefilled claims if no vp_token is present or decoded and NODE_ENV is not production', async () => {
    // 1. Initiate session
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const initBody = await initRes.json() as any;
    const sessionId = initBody.sessionId;

    // 2. Submit response with empty claims/vp_token
    const res = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(200);

    // 3. Get session status to verify fallback claims
    const sessionRes = await fetch(`${baseUrl}/api/oid4vp/session/${sessionId}`);
    const sessionBody = await sessionRes.json() as any;

    expect(sessionBody.status).toBe('verified');
    expect(sessionBody.claims.given_name).toBe('Maximilia');
    expect(sessionBody.claims.family_name).toBe('P.');
  });

  it('should block sandbox fallbacks with 401 when NODE_ENV is production', async () => {
    // 1. Initiate session
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const initBody = await initRes.json() as any;
    const sessionId = initBody.sessionId;

    // Save previous NODE_ENV
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    try {
      const realRes = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });

      expect(realRes.status).toBe(401);
      const body = await realRes.json() as any;
      expect(body.error).toBe('unauthorized');
      expect(body.details).toContain('Sandbox fallbacks disabled');
    } finally {
      // Restore previous NODE_ENV
      process.env.NODE_ENV = originalEnv;
    }
  });

  it('should verify storage-at-rest is encrypted with AES-256-GCM', async () => {
    // 1. Initiate a session to trigger a save operation
    await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });

    // 2. Read the raw sessions file from disk
    expect(existsSync(SESSIONS_FILE)).toBe(true);
    const rawContent = readFileSync(SESSIONS_FILE, 'utf-8');

    // 3. Assert that the file is written in GCM envelope format and contains no plain session IDs or claims
    const parsedFile = JSON.parse(rawContent);
    expect(parsedFile.iv).toBeDefined();
    expect(parsedFile.tag).toBeDefined();
    expect(parsedFile.content).toBeDefined();

    // Verify it contains zero raw text of active claims or keys
    expect(rawContent).not.toContain('Maximilia');
    expect(rawContent).not.toContain('SecOps');
  });

  it('should enforce HTTPS dynamically in production and throw a 403 Forbidden', async () => {
    const originalEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    try {
      // Simulate client metadata with HTTP protocol
      const res = await fetch(`${baseUrl}/api/oid4vp/client-metadata`, {
        headers: {
          'X-Forwarded-Proto': 'http',
          'X-Forwarded-Host': 'demo.vericred.com',
        },
      });

      expect(res.status).toBe(403);
      const body = await res.json() as any;
      expect(body.error).toBe('forbidden');
      expect(body.details).toContain('HTTPS is strictly required');
    } finally {
      process.env.NODE_ENV = originalEnv;
    }
  });

  it('should handle high-volume concurrent session writes without data corruption', async () => {
    const promises = Array.from({ length: 15 }).map(async () => {
      const res = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
      const body = await res.json() as any;
      return body.sessionId;
    });

    const sessionIds = await Promise.all(promises);

    // Verify all sessions were successfully created, saved, and can be retrieved
    for (const id of sessionIds) {
      const res = await fetch(`${baseUrl}/api/oid4vp/session/${id}`);
      expect(res.status).toBe(200);
      const body = await res.json() as any;
      expect(body.status).toBe('initiated');
    }
  });

  // --- CRYPTOGRAPHIC 3-TIER VALIDATION TEST CASES ---

  it('should successfully pass a valid 3-tier JWS, EUTL, and KB-JWT presentation', async () => {
    // 1. Initiate session to obtain nonce
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const { sessionId, nonce } = await initRes.json() as any;

    // 2. Load active issuer keys for SD-JWT-VC signing (Tier 1: Trust Anchor validation)
    const { privateKey, kid } = await getIssuerKeyPair();

    // Generate holder key pair and export public JWK
    const holderKeys = await generateKeyPair('ES256');
    const holderPublicKeyJwk = await exportJWK(holderKeys.publicKey);

    // 3. Issuer signs SD-JWT-VC containing the holder's key inside cnf.jwk (Tier 2: Trusted issuer EUTL check)
    const sdJwtVc = await new SignJWT({
      iss: 'http://localhost:3100',
      cnf: { jwk: holderPublicKeyJwk },
    })
      .setProtectedHeader({ alg: 'ES256', kid })
      .sign(privateKey);

    // Create selective disclosure blocks
    const d1 = Buffer.from(JSON.stringify(['salt1', 'given_name', 'Diana'])).toString('base64url');

    // 4. Holder signs ephemeral KB-JWT matching active session nonce (Tier 3: Holder binding POP)
    const kbJwt = await new SignJWT({
      nonce,
      aud: `${baseUrl}/api/oid4vp/client-metadata`,
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
      .sign(holderKeys.privateKey);

    const vpToken = `${sdJwtVc}~${d1}~${kbJwt}~`;

    // 5. Submit valid presentation
    const res = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vp_token: vpToken }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.success).toBe(true);

    // Verify session has extracted claim
    const statusRes = await fetch(`${baseUrl}/api/oid4vp/session/${sessionId}`);
    const statusBody = await statusRes.json() as any;
    expect(statusBody.claims.given_name).toBe('Diana');
  });

  it('should fail with 401 on tampered Issuer signature (Tier 1 Violation)', async () => {
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const { sessionId, nonce } = await initRes.json() as any;

    const rogueIssuerKeys = await generateKeyPair('ES256');
    const holderKeys = await generateKeyPair('ES256');
    const holderPublicKeyJwk = await exportJWK(holderKeys.publicKey);

    // Rogue untrusted key signs the credential
    const tamperedVc = await new SignJWT({
      iss: 'http://localhost:3100',
      cnf: { jwk: holderPublicKeyJwk },
    })
      .setProtectedHeader({ alg: 'ES256' })
      .sign(rogueIssuerKeys.privateKey);

    const d1 = Buffer.from(JSON.stringify(['salt1', 'given_name', 'Diana'])).toString('base64url');
    const kbJwt = await new SignJWT({
      nonce,
      aud: `${baseUrl}/api/oid4vp/client-metadata`,
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
      .sign(holderKeys.privateKey);

    const vpToken = `${tamperedVc}~${d1}~${kbJwt}~`;

    const res = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vp_token: vpToken }),
    });

    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.error).toBe('unauthorized');
    expect(body.details).toContain('Trust Anchor Violation: Issuer JWS signature verification failed');
  });

  it('should fail with 401 on untrusted Issuer (Tier 2 Violation)', async () => {
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const { sessionId, nonce } = await initRes.json() as any;

    const { privateKey, kid } = await getIssuerKeyPair();
    const holderKeys = await generateKeyPair('ES256');
    const holderPublicKeyJwk = await exportJWK(holderKeys.publicKey);

    // Valid signature but issuer is malicious-untrusted domain
    const untrustedVc = await new SignJWT({
      iss: 'https://evil-untrusted-issuer.com',
      cnf: { jwk: holderPublicKeyJwk },
    })
      .setProtectedHeader({ alg: 'ES256', kid })
      .sign(privateKey);

    const d1 = Buffer.from(JSON.stringify(['salt1', 'given_name', 'Diana'])).toString('base64url');
    const kbJwt = await new SignJWT({
      nonce,
      aud: `${baseUrl}/api/oid4vp/client-metadata`,
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
      .sign(holderKeys.privateKey);

    const vpToken = `${untrustedVc}~${d1}~${kbJwt}~`;

    const res = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vp_token: vpToken }),
    });

    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.error).toBe('unauthorized');
    expect(body.details).toContain('is not present in our trusted anchor roster');
  });

  it('should fail with 401 on mismatched Holder public key (Tier 3 Violation)', async () => {
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const { sessionId, nonce } = await initRes.json() as any;

    const { privateKey, kid } = await getIssuerKeyPair();
    const holderKeys = await generateKeyPair('ES256');
    const holderPublicKeyJwk = await exportJWK(holderKeys.publicKey);

    const sdJwtVc = await new SignJWT({
      iss: 'http://localhost:3100',
      cnf: { jwk: holderPublicKeyJwk },
    })
      .setProtectedHeader({ alg: 'ES256', kid })
      .sign(privateKey);

    const d1 = Buffer.from(JSON.stringify(['salt1', 'given_name', 'Diana'])).toString('base64url');

    // A completely different rogue holder signing key binds the KB-JWT instead of original holder key inside credential
    const rogueHolderKeys = await generateKeyPair('ES256');
    const kbJwt = await new SignJWT({
      nonce,
      aud: `${baseUrl}/api/oid4vp/client-metadata`,
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
      .sign(rogueHolderKeys.privateKey);

    const vpToken = `${sdJwtVc}~${d1}~${kbJwt}~`;

    const res = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vp_token: vpToken }),
    });

    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.error).toBe('unauthorized');
    expect(body.details).toContain('Holder Key-Binding Violation: Ephemeral KB-JWT signature verification failed');
  });

  it('should fail with 401 on mismatched Session Nonce inside KB-JWT (Tier 3 Violation)', async () => {
    const initRes = await fetch(`${baseUrl}/api/oid4vp/initiate`, { method: 'POST' });
    const { sessionId } = await initRes.json() as any;

    const { privateKey, kid } = await getIssuerKeyPair();
    const holderKeys = await generateKeyPair('ES256');
    const holderPublicKeyJwk = await exportJWK(holderKeys.publicKey);

    const sdJwtVc = await new SignJWT({
      iss: 'http://localhost:3100',
      cnf: { jwk: holderPublicKeyJwk },
    })
      .setProtectedHeader({ alg: 'ES256', kid })
      .sign(privateKey);

    const d1 = Buffer.from(JSON.stringify(['salt1', 'given_name', 'Diana'])).toString('base64url');

    // Mismatched nonce
    const kbJwt = await new SignJWT({
      nonce: 'mismatched-session-nonce-value-123',
      aud: `${baseUrl}/api/oid4vp/client-metadata`,
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
      .sign(holderKeys.privateKey);

    const vpToken = `${sdJwtVc}~${d1}~${kbJwt}~`;

    const res = await fetch(`${baseUrl}/api/oid4vp/response/${sessionId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vp_token: vpToken }),
    });

    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.error).toBe('unauthorized');
    expect(body.details).toContain('Holder Key-Binding Violation: Nonce mismatch');
  });
});
