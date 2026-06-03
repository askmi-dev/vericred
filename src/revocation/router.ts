import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { buildStatusListJWT, getListId } from './statuslist.js';
import { requireAdmin } from '../middleware/auth.js';
import { revokeCredential, getIssuedCredentials } from './statuslist.js';

export function createRevocationRouter(): Router {
  const router = createRouter();

  // Public: serve status list JWT (wallets + verifiers fetch this)
  router.get('/status/:listId', async (req, res) => {
    const listId = getListId();
    if (req.params.listId !== listId) {
      res.status(404).json({ error: 'status list not found' });
      return;
    }
    const jwt = await buildStatusListJWT();
    res.setHeader('Content-Type', 'application/jwt');
    res.send(jwt);
  });

  // Admin: revoke by credential ID
  router.post('/admin/revoke', requireAdmin, (req, res) => {
    const { credentialId } = req.body as { credentialId?: string };
    if (!credentialId) { res.status(400).json({ error: 'credentialId required' }); return; }
    const ok = revokeCredential(credentialId);
    res.json({ success: ok, message: ok ? 'Credential revoked' : 'Not found or already revoked' });
  });

  // Admin API: list all issued credentials
  router.get('/admin/api/credentials', requireAdmin, (_req, res) => {
    res.json(getIssuedCredentials());
  });

  return router;
}
