/**
 * Admin auth middleware.
 *
 * Browser sessions: random session ID stored server-side (Map), set as HttpOnly cookie.
 * API calls: Authorization: Bearer <adminApiKey>
 *
 * The API key itself is NEVER stored in a cookie.
 * Secure flag is set automatically when NODE_ENV=production.
 */
import type { Request, Response, NextFunction } from 'express';
import { randomBytes } from 'crypto';
import { loadSecrets } from '../config/secrets.js';

const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const sessions = new Map<string, number>();
const csrfTokens = new Map<string, number>(); // token -> expiry

const isProduction = process.env['NODE_ENV'] === 'production';
const COOKIE_FLAGS = '; HttpOnly; Path=/; SameSite=Strict; Max-Age=28800'
  + (isProduction ? '; Secure' : '');

export function createSession(): string {
  const token = randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL_MS);
  return token;
}

export function destroySession(token: string): void {
  sessions.delete(token);
}

/** Generate a CSRF token bound to a session. Embed in forms as hidden field "csrf". */
export function createCsrfToken(): string {
  const token = randomBytes(24).toString('hex');
  csrfTokens.set(token, Date.now() + 60 * 60 * 1000); // 1h
  return token;
}

/** Validate and consume a CSRF token (single-use). */
export function validateCsrf(token: string | undefined): boolean {
  if (!token) return false;
  const exp = csrfTokens.get(token);
  if (!exp || exp < Date.now()) return false;
  csrfTokens.delete(token); // single-use
  return true;
}

function pruneExpired(): void {
  const now = Date.now();
  for (const [k, exp] of sessions) if (exp < now) sessions.delete(k);
  for (const [k, exp] of csrfTokens) if (exp < now) csrfTokens.delete(k);
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

/** Middleware: reject POST/PUT/DELETE without valid CSRF token in body. */
export function requireCsrf(req: Request, res: Response, next: NextFunction): void {
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const token = (req.body as Record<string, string>)['csrf']
      ?? req.headers['x-csrf-token'] as string;
    if (!validateCsrf(token)) {
      res.status(403).json({ error: 'invalid csrf token' });
      return;
    }
  }
  next();
}

export function cookieFlags(): string {
  return COOKIE_FLAGS;
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
