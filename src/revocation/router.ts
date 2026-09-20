import { asyncHandler } from '../middleware/errors.js';
import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { buildStatusListJWT, buildTokenStatusListJWT, getListId, hasList } from './statuslist.js';
import { requireAdmin, requireCsrf } from '../middleware/auth.js';
import { revokeCredential, getIssuedCredentials } from './statuslist.js';
import { maskCredentialRecord } from '../admin/masking.js';

export function createRevocationRouter(): Router {
  const router = createRouter();

  router.get('/status/token/:listId', asyncHandler(async (req, res) => {
    if (!hasList(req.params.listId)) { res.status(404).json({ error: 'status list not found' }); return; }
    res.setHeader('Cache-Control', 'public, max-age=60');
    res.type('application/statuslist+jwt').send(await buildTokenStatusListJWT(req.params.listId));
  }));

  // Public: serve status list JWT (wallets + verifiers fetch this)
  router.get('/status/:listId', asyncHandler(async (req, res) => {
    const listId = req.params.listId;
    if (!hasList(listId)) {
      res.status(404).json({ error: 'status list not found' });
      return;
    }
    const jwt = await buildStatusListJWT(listId);
    res.setHeader('Content-Type', 'application/jwt');
    res.send(jwt);
  }));

  // Admin: revoke by credential ID
  router.post('/admin/revoke', requireAdmin, requireCsrf, (req, res) => {
    const { credentialId, reason } = req.body as { credentialId?: string; reason?: string };
    if (!credentialId) { res.status(400).json({ error: 'credentialId required' }); return; }
    const ok = revokeCredential(credentialId, reason, res.locals.actor);
    res.json({ success: ok, message: ok ? 'Credential revoked' : 'Not found or already revoked' });
  });

  // Admin API: list all issued credentials
  router.get('/admin/api/credentials', requireAdmin, (_req, res) => {
    const credentials = getIssuedCredentials();
    if (process.env['PII_ADMIN_MODE'] === 'true') {
      res.json(credentials);
    } else {
      res.json(credentials.map(c => maskCredentialRecord(c as unknown as Record<string, unknown>)));
    }
  });

  return router;
}
