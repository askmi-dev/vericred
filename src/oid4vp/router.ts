import { registrationInfo } from '../wallet/registration.js';
import { Router } from 'express';
import { SignJWT, type JWK } from 'jose';
import { certificateSigner, getWalletProfile, type WalletProfile } from '../wallet/profile.js';
import { decryptMessage, newEncryptionKey, encryptionMethods } from '../wallet/encryption.js';
import { randomBytes, createHash, createCipheriv, createDecipheriv } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import qrcode from 'qrcode';
import { credentialVct } from '../credentials/registry.js';
import { loadConfig } from '../config/loader.js';
import { loadSecrets } from '../config/secrets.js';
import { atomicWrite } from '../storage/atomic.js';
import { verifyPresentation, presentationProfiles } from './verify.js';

interface Session {
  status: 'initiated' | 'verified';
  protocol?: 'openid4vp-1.0' | 'legacy-draft';
  nonce: string; readTokenHash: string; credentialType: string;
  walletProfile?: WalletProfile; issuerUrl?: string; clientId?: string; encryptionKey?: { publicKey: JWK; privateKey: JWK };
  createdAt: number; claims: Record<string, unknown> | null;
}
const inFlight = new Set<string>();
const digest = (text: string) => createHash('sha256').update(text).digest('hex');
const path = () => (process.env.DATA_DIR ?? './data') + '/oid4vp_sessions.json';
const key = () => createHash('sha256').update('vericred-presentation-store:' + loadSecrets().pseudonymSecret).digest();
function load(): Record<string, Session> {
  if (!existsSync(path())) return {};
  const envelope = JSON.parse(readFileSync(path(), 'utf8'));
  // Old sessions used a different contract and must be reinitiated.
  if (envelope.version !== 2) return {};
  const decipher = createDecipheriv('aes-256-gcm', key(), Buffer.from(envelope.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'hex'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.content, 'hex')), decipher.final()]).toString('utf8'));
}
function save(sessions: Record<string, Session>) {
  for (const [id, session] of Object.entries(sessions)) {
    if (Date.now() - session.createdAt >= 30 * 60_000) delete sessions[id];
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(), iv);
  const content = Buffer.concat([cipher.update(JSON.stringify(sessions)), cipher.final()]);
  atomicWrite(path(), JSON.stringify({ version: 2, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), content: content.toString('hex') }));
}
function get(id: string): Session | undefined {
  const s = load()[id];
  return s && Date.now() - s.createdAt < 30 * 60_000 &&
    (s.walletProfile ?? 'custom') === getWalletProfile() && (!s.issuerUrl || s.issuerUrl === baseUrl()) ? s : undefined;
}
function baseUrl(): string {
  const url = new URL(loadConfig().issuer.url);
  if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') throw new Error('HTTPS issuer URL required');
  return url.href.replace(/\/$/, '');
}
function clientMetadata() {
  return { client_name: 'VeriCred Verifier', vp_formats_supported: {
    'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
  } };
}
function requestFor(id: string, s: Session) {
  const base = s.issuerUrl ?? baseUrl();
  const responseUri = base + '/api/oid4vp/response/' + id;
  if (s.protocol === 'openid4vp-1.0') {
    return { client_id: s.clientId ?? 'redirect_uri:' + responseUri, response_uri: responseUri,
      response_mode: s.walletProfile === 'eudi-android' ? 'direct_post.jwt' : 'direct_post', response_type: 'vp_token', nonce: s.nonce, state: id,
      client_metadata: { ...clientMetadata(), ...(s.encryptionKey ? { jwks: { keys: [s.encryptionKey.publicKey] }, encrypted_response_enc_values_supported: encryptionMethods } : {}) },
      dcql_query: { credentials: [{ id: 'credential', format: 'dc+sd-jwt',
        meta: { vct_values: [credentialVct(s.credentialType)] },
        claims: presentationProfiles[s.credentialType].map(name => ({ path: [name],
          ...(name === 'age_over_18' ? { values: [true] } : {}) })),
      }] },
    };
  }
  // Explicit draft adapter retained for existing integrations; not a signed Request Object.
  return { client_id: base + '/api/oid4vp/client-metadata', response_uri: responseUri,
    response_mode: 'direct_post', response_type: 'vp_token', nonce: s.nonce,
    presentation_definition: { id, input_descriptors: [{ id: s.credentialType,
      format: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] } },
      constraints: { fields: presentationProfiles[s.credentialType].map(name => ({ path: ['$.' + name], intent_to_retain: false })) },
    }] } };
}
export function createOid4vpRouter() {
  const router = Router();
  router.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });
  router.post('/api/oid4vp/initiate', async (req, res) => {
    try {
      const credentialType = req.body?.credentialType ?? loadConfig().credential.type;
      if (typeof credentialType !== 'string' || !Object.hasOwn(presentationProfiles, credentialType)) {
        res.status(400).json({ error: 'unsupported_credential_type' }); return;
      }
      const protocol = req.body?.protocol ?? 'openid4vp-1.0';
      if (!['openid4vp-1.0', 'legacy-draft'].includes(protocol)) {
        res.status(400).json({ error: 'unsupported_protocol' }); return;
      }
      const base = baseUrl();
      const walletProfile = getWalletProfile();
      if (walletProfile === 'eudi-android' && protocol !== 'openid4vp-1.0') {
        res.status(400).json({ error: 'legacy_not_available_in_eudi_profile' }); return;
      }
      const signer = walletProfile === 'eudi-android' ? await certificateSigner('verifier') : null;
      if (signer) await registrationInfo('verifier');
      const encryptionKey = signer ? await newEncryptionKey() : undefined;
      const sessionId = 'sess-' + randomBytes(32).toString('hex');
      const readToken = randomBytes(32).toString('base64url');
      const nonce = randomBytes(32).toString('base64url');
      const session: Session = { status: 'initiated', protocol, nonce, credentialType, walletProfile, issuerUrl: base,
        ...(signer ? { clientId: signer.clientId, encryptionKey } : {}),
        readTokenHash: digest(readToken), createdAt: Date.now(), claims: null };
      const params = new URLSearchParams();
      for (const [name, value] of Object.entries(requestFor(sessionId, session))) {
        params.set(name, typeof value === 'string' ? value : JSON.stringify(value));
      }
      const requestUri = signer ? 'openid4vp://authorize?' + new URLSearchParams({ client_id: signer.clientId, request_uri: base + '/api/oid4vp/request/' + sessionId }).toString()
        : protocol === 'openid4vp-1.0' ? 'openid4vp://authorize?' + params.toString()
        : 'openid-vp://?client_id=' + encodeURIComponent(base + '/api/oid4vp/client-metadata') + '&request_uri=' + encodeURIComponent(base + '/api/oid4vp/request/' + sessionId);
      const qrCodeDataUrl = await qrcode.toDataURL(requestUri);
      const sessions = load();
      sessions[sessionId] = session;
      save(sessions);
      res.json({ success: true, protocol, sessionId, readToken, nonce, requestUri, qrCodeDataUrl });
    } catch { res.status(503).json({ error: 'verifier_unavailable' }); }
  });
  router.get('/api/oid4vp/client-metadata', (_req, res) => {
    try {
      res.json({ ...clientMetadata(), client_id: baseUrl() + '/api/oid4vp/client-metadata' });
    } catch { res.status(503).json({ error: 'verifier_unavailable' }); }
  });
  router.get('/api/oid4vp/request/:sessionId', async (req, res) => {
    try {
      const s = get(req.params.sessionId);
      if (!s || s.status !== 'initiated') { res.status(404).json({ error: 'session_not_found' }); return; }
      const request = requestFor(req.params.sessionId, s);
      if (s.walletProfile === 'eudi-android') {
        const signer = await certificateSigner('verifier');
        if (signer.clientId !== s.clientId) throw new Error('Verifier identity changed');
        const jwt = await new SignJWT({ ...request, verifier_info: await registrationInfo('verifier') })
          .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: signer.x5c })
          .setIssuer(signer.clientId).setAudience('https://self-issued.me/v2').setIssuedAt()
          .setExpirationTime(Math.min(Math.floor(Date.now() / 1000) + 300, Math.floor(s.createdAt / 1000) + 1800))
          .sign(signer.privateKey);
        res.type('application/oauth-authz-req+jwt').send(jwt); return;
      }
      res.json(request);
    } catch { res.status(503).json({ error: 'verifier_unavailable' }); }
  });
  router.post('/api/oid4vp/response/:sessionId', async (req, res) => {
    const id = req.params.sessionId;
    if (inFlight.has(id)) { res.status(409).json({ error: 'session_consumed' }); return; }
    inFlight.add(id);
    try {
      const s = get(id);
      if (!s) { res.status(404).json({ error: 'session_not_found' }); return; }
      if (s.status !== 'initiated') { res.status(409).json({ error: 'session_consumed' }); return; }
      let claims;
      try {
        let response = req.body;
        if (s.walletProfile === 'eudi-android') {
          if (!s.encryptionKey || !response || Object.keys(response).length !== 1) throw new Error('Encrypted response required');
          response = await decryptMessage(response.response, s.encryptionKey.privateKey);
        }
        let vp = response?.vp_token;
        if (s.protocol === 'openid4vp-1.0') {
          if (response?.state !== id) throw new Error('Wrong state');
          if (typeof vp === 'string') vp = JSON.parse(vp);
          if (!vp || typeof vp !== 'object' || Object.keys(vp).length !== 1 ||
              !Array.isArray(vp.credential) || vp.credential.length !== 1) throw new Error('Invalid DCQL response');
          vp = vp.credential[0];
        }
        claims = await verifyPresentation(vp, s.nonce, requestFor(id, s).client_id, s.credentialType, s.protocol);
      }
      catch { res.status(401).json({ error: 'invalid_presentation' }); return; }
      const sessions = load();
      sessions[id] = { ...s, status: 'verified', claims };
      save(sessions);
      res.json({ success: true, status: 'verified' });
    } catch { res.status(503).json({ error: 'verifier_unavailable' }); }
    finally { inFlight.delete(id); }
  });
  router.get('/api/oid4vp/session/:sessionId', (req, res) => {
    try {
      const s = get(req.params.sessionId);
      const token = req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : '';
      if (!s || !token || digest(token) !== s.readTokenHash) { res.status(401).json({ error: 'unauthorized' }); return; }
      res.json({ status: s.status, claims: s.claims });
    } catch { res.status(503).json({ error: 'verifier_unavailable' }); }
  });
  return router;
}
