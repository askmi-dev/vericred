/**
 * Admin auth middleware.
 *
 * Browser sessions: random session ID stored server-side (Map), set as HttpOnly cookie.
 * API calls: Authorization: Bearer <adminApiKey>
 *
 * The API key itself is NEVER stored in a cookie.
 */
import type { Request, Response, NextFunction } from 'express';
import { randomBytes } from 'crypto';
import { loadSecrets } from '../config/secrets.js';

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const sessions = new Map<string, number>();

export function createSession(): string {
  const token = randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

export function destroySession(token: string): void {
  sessions.delete(token);
}

function pruneExpired(): void {
  const now = Date.now();
  for (const [k, exp] of sessions) {
    if (exp < now) sessions.delete(k);
  }
}

function isValidSession(token: string): boolean {
  pruneExpired();
  const exp = sessions.get(token);
  return exp !== undefined && exp > Date.now();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const secrets = loadSecrets();

  const bearer = req.headers.authorization?.replace('Bearer ', '').trim();
  if (bearer && bearer === secrets.adminApiKey) {
    next();
    return;
  }

  const cookie = parseCookies(req.headers.cookie ?? '')['admin_session'];
  if (cookie && isValidSession(cookie)) {
    next();
    return;
  }

  if (req.headers.accept?.includes('text/html')) {
    res.redirect('/admin/login');
    return;
  }

  res.status(401).json({ error: 'unauthorized' });
}

function parseCookies(header: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    try {
      result[decodeURIComponent(part.slice(0, idx).trim())] =
        decodeURIComponent(part.slice(idx + 1).trim());
    } catch { /* ignore malformed */ }
  }
  return result;
}
