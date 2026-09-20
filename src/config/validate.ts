import { z } from 'zod';
import type { VeriCredConfig } from './types.js';
import { sqlIdentifier } from '../connectors/sql.js';

const mapping = z.record(z.string().min(1));
const httpUrl = z.string().url().refine(value => {
  const url = new URL(value);
  return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && !url.hash && !url.search;
}, 'Use an HTTP(S) URL without credentials, query or fragment');
const schema = z.object({
  revision: z.number().int().nonnegative().optional(),
  issuer: z.object({ name: z.string().trim().min(1).max(200), url: httpUrl, did: z.string() }).strict(),
  credential: z.object({ type: z.string().min(1), expiresInDays: z.number().int().min(1).max(3650), format: z.enum(['dc+sd-jwt', 'vc+sd-jwt']).optional() }).strict(),
  templateOptions: z.record(z.unknown()).optional(),
  fieldMappings: mapping,
  templateMappings: z.record(mapping).optional(),
  templateOptionsByType: z.record(z.record(z.unknown())).optional(),
  dataSource: z.object({
    type: z.enum(['json', 'postgres', 'mysql', 'rest', 'csv', 'manual']),
    path: z.string().min(1).optional(), connectionString: z.string().min(1).optional(),
    table: z.string().min(1).optional(), identifierColumn: z.string().min(1).optional(),
    endpoint: z.string().min(1).optional(), authHeader: z.string().optional(), healthCheckIdentifier: z.string().min(1).optional(),
  }).strict(),
}).strict();
export function validateConfig(input: unknown): VeriCredConfig {
  const config = schema.parse(input);
  if (new URL(config.issuer.url).pathname !== '/') throw new Error('Issuer URL must be an origin without a path; subpath hosting is not supported');
  config.issuer.url = config.issuer.url.replace(/\/$/, '');
  if (process.env.NODE_ENV === 'production' && new URL(config.issuer.url).protocol !== 'https:') throw new Error('Production requires an HTTPS issuer URL');
  const ds = config.dataSource;
  if (['json', 'csv'].includes(ds.type) && !ds.path) throw new Error('File source requires a path');
  if (ds.type === 'postgres' || ds.type === 'mysql') {
    if (!ds.connectionString) throw new Error('Database source requires connectionString');
    const url = new URL(ds.connectionString);
    if (!(ds.type === 'postgres' ? ['postgres:', 'postgresql:'] : ['mysql:']).includes(url.protocol)) throw new Error('Database connection string has the wrong protocol');
    sqlIdentifier(ds.table ?? 'users', '"', true);
    sqlIdentifier(ds.identifierColumn ?? 'email', '"');
  }
  if (ds.type === 'rest') {
    if (!ds.endpoint?.includes('{id}') || !ds.healthCheckIdentifier) throw new Error('REST requires an endpoint containing {id} and healthCheckIdentifier');
    httpUrl.parse(ds.endpoint.replaceAll('{id}', 'probe'));
  }
  return config as VeriCredConfig;
}
