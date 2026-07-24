import { Router as createRouter, urlencoded } from 'express';
import type { Router, Request, Response } from 'express';
import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync } from 'fs';
import { dirname } from 'path';
import qrcode from 'qrcode';
import { importJWK, jwtVerify } from 'jose';
import type { JWK } from 'jose';
import { loadConfig } from '../config/loader.js';
import { loadSecrets } from '../config/secrets.js';
import { getAllPublicKeys } from '../keys/manager.js';

interface Oid4vpSession {
  status: 'initiated' | 'verified';
  nonce: string;
  requestUri: string;
  claims: Record<string, unknown> | null;
  vpToken?: string;
  timestamp: number;
}

const DATA_DIR = process.env.DATA_DIR ?? '.';
const SESSIONS_FILE = `${DATA_DIR}/oid4vp_sessions.json`;

// Cryptographic helpers for AES-256-GCM encryption-at-rest
function getEncryptionKey(): Buffer {
  const secrets = loadSecrets();
  return createHash('sha256').update(secrets.pseudonymSecret).digest();
}

function encrypt(text: string): { iv: string; content: string; tag: string } {
  const key = getEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return {
    iv: iv.toString('hex'),
    content: encrypted,
    tag,
  };
}

function decrypt(enc: { iv: string; content: string; tag: string }): string {
  const key = getEncryptionKey();
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(enc.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(enc.tag, 'hex'));
  let decrypted = decipher.update(enc.content, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

class Oid4vpSessionStore {
  private cache = new Map<string, Oid4vpSession>();

  constructor() {
    this.load();
  }

  private load() {
    try {
      if (existsSync(SESSIONS_FILE)) {
        const rawData = readFileSync(SESSIONS_FILE, 'utf-8');
        if (!rawData.trim()) return;

        let decryptedData = rawData;
        if (rawData.startsWith('{') && rawData.includes('"tag"') && rawData.includes('"content"')) {
          const enc = JSON.parse(rawData);
          decryptedData = decrypt(enc);
        }

        const parsed = JSON.parse(decryptedData);
        this.cache.clear();
        for (const [k, v] of Object.entries(parsed)) {
          this.cache.set(k, v as Oid4vpSession);
        }
      }
    } catch (err) {
      console.error('[oid4vp] Failed to load/decrypt sessions:', err);
    }
  }

  private save() {
    try {
      const obj = Object.fromEntries(this.cache.entries());
      const now = Date.now();
      const expiryWindow = 30 * 60 * 1000; // 30 minutes TTL to prevent storage bloat
      for (const [k, v] of this.cache.entries()) {
        if (now - v.timestamp > expiryWindow) {
          this.cache.delete(k);
          delete obj[k];
        }
      }

      // Serialize and encrypt the session state before writing to disk
      const serialized = JSON.stringify(obj);
      const encrypted = encrypt(serialized);
      const rawToWrite = JSON.stringify(encrypted, null, 2);

      mkdirSync(dirname(SESSIONS_FILE), { recursive: true });

      // Atomic, transaction-safe write-and-rename to prevent JSON corruption under load
      const tmpFile = `${SESSIONS_FILE}.tmp`;
      writeFileSync(tmpFile, rawToWrite);
      renameSync(tmpFile, SESSIONS_FILE);
    } catch (err) {
      console.error('[oid4vp] Failed to atomically save/encrypt sessions:', err);
    }
  }

  get(sessionId: string): Oid4vpSession | undefined {
    this.load(); // Refresh from the encrypted persistent store to handle multi-instance setups
    return this.cache.get(sessionId);
  }

  set(sessionId: string, session: Oid4vpSession) {
    this.cache.set(sessionId, session);
    this.save();
  }
}

const sessionStore = new Oid4vpSessionStore();

// Dynamically resolves host and enforces HTTPS protocol-level check in production
function getBaseUrl(req: Request): string {
  const config = loadConfig();
  const host = (req.headers['x-forwarded-host'] as string) || req.get('host');
  if (!host) return config.issuer.url;
  const protocol = (req.headers['x-forwarded-proto'] as string) || req.protocol || 'http';

  // Strict Production HTTPS Guard to prevent insecure HTTP leaking in production environments
  if (process.env.NODE_ENV === 'production' && protocol !== 'https') {
    throw new Error('Insecure protocol detected. HTTPS is strictly required in production mode.');
  }

  return `${protocol}://${host}`;
}

export function createOid4vpRouter(): Router {
  const router = createRouter();

  // 1. Initiate Session & Return QR Code
  router.post('/api/oid4vp/initiate', async (req: Request, res: Response) => {
    try {
      const baseUrl = getBaseUrl(req);
      const sessionId = `sess-${uuidv4().substring(0, 8)}`;
      const nonce = `nonce-${randomBytes(8).toString('hex')}`;
      const requestUri = `openid-vp://?client_id=${baseUrl}/api/oid4vp/client-metadata&request_uri=${baseUrl}/api/oid4vp/request/${sessionId}`;

      let qrCodeDataUrl = '';
      try {
        qrCodeDataUrl = await qrcode.toDataURL(requestUri);
      } catch (err) {
        console.error('[oid4vp] QR Code generation failed:', err);
        qrCodeDataUrl = `MOCK_QR_BASE64_FOR_${sessionId}`;
      }

      const session: Oid4vpSession = {
        status: 'initiated',
        nonce,
        requestUri,
        claims: null,
        timestamp: Date.now(),
      };

      sessionStore.set(sessionId, session);

      console.log(`[oid4vp] Session Initiated: ${sessionId} with nonce: ${nonce}`);

      res.json({
        success: true,
        sessionId,
        nonce,
        requestUri,
        qrCodeDataUrl,
      });
    } catch (err) {
      console.error('[oid4vp] Initiate endpoint error:', err);
      res.status(500).json({ error: 'internal_server_error', details: (err as Error).message });
    }
  });

  // 2. Client Metadata
  router.get('/api/oid4vp/client-metadata', (req: Request, res: Response) => {
    try {
      const baseUrl = getBaseUrl(req);

      res.json({
        client_id: `${baseUrl}/api/oid4vp/client-metadata`,
        client_name: 'VeriCred Secure Verifier',
        response_types_supported: ['vp_token'],
        vp_formats_supported: {
          'vc+sd-jwt': {
            'sd-jwt_alg_values_supported': ['ES256'],
          },
        },
      });
    } catch (err) {
      res.status(403).json({ error: 'forbidden', details: (err as Error).message });
    }
  });

  // 3. Authorization Request Object
  router.get('/api/oid4vp/request/:sessionId', (req: Request, res: Response) => {
    try {
      const { sessionId } = req.params;
      const session = sessionStore.get(sessionId);

      if (!session) {
        res.status(404).json({ error: 'session_not_found' });
        return;
      }

      const baseUrl = getBaseUrl(req);

      res.json({
        client_id: `${baseUrl}/api/oid4vp/client-metadata`,
        response_uri: `${baseUrl}/api/oid4vp/response/${sessionId}`,
        response_mode: 'direct_post',
        response_type: 'vp_token',
        nonce: session.nonce,
        presentation_definition: {
          id: `presentation_${sessionId}`,
          input_descriptors: [
            {
              id: 'eu.europa.ec.eudiw.pid.1',
              format: {
                'vc+sd-jwt': {
                  'sd-jwt_alg_values': ['ES256'],
                },
              },
              constraints: {
                fields: [
                  {
                    path: ['$.given_name'],
                    intent_to_retain: 'true',
                  },
                  {
                    path: ['$.family_name'],
                    intent_to_retain: 'true',
                  },
                  {
                    path: ['$.age'],
                    intent_to_retain: 'true',
                  },
                ],
              },
            },
          ],
        },
      });
    } catch (err) {
      res.status(403).json({ error: 'forbidden', details: (err as Error).message });
    }
  });

  // 4. Receive Wallet Presentation (Direct Post) - explicitly handles standard urlencoded post and json payloads
  router.post('/api/oid4vp/response/:sessionId', urlencoded({ extended: true }), async (req: Request, res: Response) => {
    try {
      const { sessionId } = req.params;
      const session = sessionStore.get(sessionId);

      if (!session) {
        res.status(404).json({ error: 'session_not_found' });
        return;
      }

      const vpToken = (req.body.vp_token || req.body.vpToken || '') as string;
      const claims: Record<string, unknown> = {};

      const isMockToken = !vpToken || vpToken.startsWith('FAKE_JWT_HEADER') || vpToken.startsWith('FAKE_JWT~') || vpToken === 'FAKE_MOCK_TOKEN';

      if (isMockToken) {
        // Enforce that mock bypass is strictly forbidden in production mode
        if (process.env.NODE_ENV === 'production') {
          res.status(401).json({ error: 'unauthorized', details: 'Trust Anchor Violation: Sandbox fallbacks disabled in production mode.' });
          return;
        }
      } else {
        // --- 3-Tier Cryptographic Inbound Verification Pipeline ---
        const parts = vpToken.split('~');
        const sdJwtVc = parts[0];
        if (!sdJwtVc) {
          res.status(401).json({ error: 'unauthorized', details: 'Cryptographic Violation: Missing signed SD-JWT-VC base payload.' });
          return;
        }

        // TIER 1: Cryptographic JWS Signature Verification
        let verifiedPayload: any = null;
        let signatureOk = false;
        const publicKeys = await getAllPublicKeys();

        for (const pk of publicKeys) {
          try {
            const keyLike = await importJWK(pk.publicKey, 'ES256');
            const { payload } = await jwtVerify(sdJwtVc, keyLike);
            verifiedPayload = payload;
            signatureOk = true;
            break;
          } catch (e) {
            // Keep trying other active or historical trust anchor keys
          }
        }

        if (!signatureOk || !verifiedPayload) {
          res.status(401).json({ error: 'unauthorized', details: 'Trust Anchor Violation: Issuer JWS signature verification failed against trusted keys.' });
          return;
        }

        // TIER 2: Trusted Issuer Roster Check (EUTL Mock)
        const config = loadConfig();
        const trustedIssuers = [config.issuer.did, config.issuer.url, 'http://localhost:3100', 'https://localhost:3100'];
        if (!trustedIssuers.includes(verifiedPayload.iss)) {
          res.status(401).json({ error: 'unauthorized', details: `Trust Anchor Violation: Issuer "${verifiedPayload.iss}" is not present in our trusted anchor roster.` });
          return;
        }

        // TIER 3: Ephemeral Holder Key-Binding (KB-JWT) Verification
        const cnf = verifiedPayload.cnf as { jwk: JWK } | undefined;
        if (!cnf || !cnf.jwk) {
          res.status(401).json({ error: 'unauthorized', details: 'Holder Key-Binding Violation: Verified credential is missing the embedded cnf.jwk claim.' });
          return;
        }

        // Extract KB-JWT from token parts (usually the last non-empty part splitting by '~')
        let kbJwt: string | null = null;
        for (let i = parts.length - 1; i >= 1; i--) {
          const p = parts[i];
          if (p && p.split('.').length === 3) {
            kbJwt = p;
            break;
          }
        }

        if (!kbJwt) {
          res.status(401).json({ error: 'unauthorized', details: 'Holder Key-Binding Violation: Missing Holder Proof-of-Possession signature (KB-JWT).' });
          return;
        }

        try {
          const holderKey = await importJWK(cnf.jwk, 'ES256');
          const { payload: kbPayload } = await jwtVerify(kbJwt, holderKey, {
            audience: `${getBaseUrl(req)}/api/oid4vp/client-metadata`,
            clockTolerance: 30,
          });

          // Check that the KB-JWT is bound to the active session nonce
          if (kbPayload.nonce !== session.nonce) {
            res.status(401).json({ error: 'unauthorized', details: `Holder Key-Binding Violation: Nonce mismatch. Expected "${session.nonce}", got "${kbPayload.nonce}".` });
            return;
          }
        } catch (e) {
          res.status(401).json({ error: 'unauthorized', details: 'Holder Key-Binding Violation: Ephemeral KB-JWT signature verification failed: ' + (e as Error).message });
          return;
        }
      }

      // If checks passed or sandbox mock is allowed, parse disclosures
      if (vpToken) {
        const parts = vpToken.split('~');
        for (let i = 1; i < parts.length; i++) {
          const part = parts[i];
          if (!part || part.split('.').length === 3) continue; // Skip JWS parts (e.g. KB-JWT)
          try {
            const decoded = Buffer.from(part, 'base64url').toString('utf-8');
            const [salt, name, value] = JSON.parse(decoded) as [string, string, unknown];
            claims[name] = value;
          } catch (e) {
            // Skip non-disclosure blocks
          }
        }
      }

      // Fail-Closed Guard: Ensure sandbox fallbacks are STRICTLY disabled in production mode
      const isSandboxFallbackTriggered = Object.keys(claims).length === 0;
      if (isSandboxFallbackTriggered) {
        if (process.env.NODE_ENV === 'production') {
          console.error(`[oid4vp] Security Check: Rejected blank/invalid presentation for session ${sessionId}. Sandbox fallbacks are disabled in production mode.`);
          res.status(401).json({ error: 'unauthorized', details: 'Sandbox fallbacks disabled in production mode.' });
          return;
        }

        // Fallback only if NOT in production to keep mock/offline flow intact
        const bodyClaims = req.body.claims || {};
        claims['given_name'] = bodyClaims.given_name || bodyClaims.givenName || 'Maximilia';
        claims['family_name'] = bodyClaims.family_name || bodyClaims.familyName || 'P.';
        claims['age'] = Number(bodyClaims.age || 28);
        claims['professional_role'] = bodyClaims.professional_role || bodyClaims.professionalRole || 'SecOps Auditor';
      }

      session.status = 'verified';
      session.claims = claims;
      session.vpToken = vpToken;

      sessionStore.set(sessionId, session);

      console.log(`[oid4vp] Presentation verified successfully for session: ${sessionId}`);

      res.json({
        success: true,
        status: 'verified',
      });
    } catch (err) {
      res.status(500).json({ error: 'internal_server_error', details: (err as Error).message });
    }
  });

  // 5. Get Session Status
  router.get('/api/oid4vp/session/:sessionId', (req: Request, res: Response) => {
    const { sessionId } = req.params;
    const session = sessionStore.get(sessionId);

    if (!session) {
      res.status(404).json({ error: 'session_not_found' });
      return;
    }

    res.json(session);
  });

  return router;
}
