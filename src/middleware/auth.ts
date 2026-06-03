/**
 * Admin auth middleware.
 * Accepts either:
 *   - Authorization: Bearer <adminApiKey>  (for API calls)
 *   - Cookie: admin_session=<adminApiKey>  (for browser sessions after login)
 */
import type { Request, Response, NextFunction } from 'express';
import { loadSecrets } from '../config/secrets.js';

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const secrets = loadSecrets();

  const bearer = req.headers.authorization?.replace('Bearer ', '');
  const cookie = parseCookies(req.headers.cookie ?? '')['admin_session'];
  const token = bearer ?? cookie;

  if (token === secrets.adminApiKey) {
    next();
    return;
  }

  // HTML request → redirect to login
  if (req.headers.accept?.includes('text/html')) {
    res.redirect('/admin/login');
    return;
  }

  res.status(401).json({ error: 'unauthorized' });
}

function parseCookies(header: string): Record<string, string> {
  return Object.fromEntries(
    header.split(';').map(c => c.trim().split('=').map(decodeURIComponent))
  );
}
