import { Router as createRouter } from 'express';
import type { Router } from 'express';
import { buildStatusListJWT, getListId } from './statuslist.js';
import { requireAdmin, requireCsrf } from '../middleware/auth.js';
import { revokeCredential, getIssuedCredentials, searchCredentials, getCredentialById } from './statuslist.js';
import { maskCredentialRecord } from '../admin/masking.js';
import { getSessionId } from '../middleware/auth.js';

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
  router.post('/admin/revoke', requireAdmin, requireCsrf, (req, res) => {
    const { credentialId, reason } = req.body as { credentialId?: string; reason?: string };
    if (!credentialId) { res.status(400).json({ error: 'credentialId required' }); return; }
    const ok = revokeCredential(credentialId, reason);
    res.json({ success: ok, message: ok ? 'Credential revoked' : 'Not found or already revoked' });
  });

  // Admin API: list all issued credentials (with optional search)
  router.get('/admin/api/credentials', requireAdmin, (req, res) => {
    const { search, status } = req.query as { search?: string; status?: string };
    let credentials = getIssuedCredentials();
    
    // Apply search filter if provided
    if (search) {
      credentials = searchCredentials(search);
    }
    
    // Apply status filter if provided
    if (status) {
      const isRevoked = status.toLowerCase() === 'revoked';
      credentials = credentials.filter(c => c.revoked === isRevoked);
    }
    
    if (process.env['PII_ADMIN_MODE'] === 'true') {
      res.json(credentials);
    } else {
      res.json(credentials.map(c => maskCredentialRecord(c as Record<string, unknown>)));
    }
  });

  // Admin API: get single credential by ID
  router.get('/admin/api/credentials/:credentialId', requireAdmin, (req, res) => {
    const { credentialId } = req.params;
    const credential = getCredentialById(credentialId);
    
    if (!credential) {
      res.status(404).json({ error: 'Credential not found' });
      return;
    }
    
    if (process.env['PII_ADMIN_MODE'] === 'true') {
      res.json(credential);
    } else {
      res.json(maskCredentialRecord(credential as Record<string, unknown>));
    }
  });

  // Admin API: revoke credential by ID (alternative endpoint for one-click revocation)
  router.post('/admin/api/credentials/:credentialId/revoke', requireAdmin, requireCsrf, (req, res) => {
    const { credentialId } = req.params;
    const { reason } = req.body as { reason?: string };
    
    if (!credentialId) {
      res.status(400).json({ error: 'credentialId required' });
      return;
    }
    
    const credential = getCredentialById(credentialId);
    if (!credential) {
      res.status(404).json({ error: 'Credential not found' });
      return;
    }
    
    const ok = revokeCredential(credentialId, reason || 'Administrative Revocation');
    
    // Get the updated credential after revocation
    const updatedCredential = getCredentialById(credentialId);
    
    res.json({ 
      success: ok, 
      message: ok ? 'Credential revoked' : 'Already revoked',
      credential: process.env['PII_ADMIN_MODE'] === 'true' ? updatedCredential : maskCredentialRecord(updatedCredential as Record<string, unknown>)
    });
  });

  return router;
}
