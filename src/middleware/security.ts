import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

export function securityHeaders(dist: string) {
  const hashes = new Set<string>();
  function scan(dir: string) {
    if (!existsSync(dir)) return;
    for (const file of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, file.name);
      if (file.isDirectory()) scan(path);
      else if (file.name.endsWith('.html')) {
        for (const match of readFileSync(path, 'utf8').matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
          if (!/\bsrc\s*=/i.test(match[1]) && match[2].trim()) hashes.add("'sha256-" + createHash('sha256').update(match[2]).digest('base64') + "'");
        }
      }
    }
  }
  scan(dist);
  return helmet({
    contentSecurityPolicy: { directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-eval'", ...hashes],
      scriptSrcAttr: ["'none'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
    }},
  });
}
export const publicLimiter = () => rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false });
export const loginLimiter = () => rateLimit({ windowMs: 15 * 60_000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
