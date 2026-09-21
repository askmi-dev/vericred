import type { Request, Response, NextFunction, RequestHandler } from 'express';
export function asyncHandler(handler: (req: Request, res: Response, next: NextFunction) => unknown): RequestHandler {
  return (req, res, next) => { Promise.resolve().then(() => handler(req, res, next)).catch(next); };
}
export function errorHandler(error: unknown, _req: Request, res: Response, next: NextFunction) {
  if (res.headersSent) { next(error); return; }
  console.error('[request] Operation failed');
  res.status(503).json({ error: 'service_unavailable' });
}
