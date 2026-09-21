import { deriveHolderPassword } from '../config/secrets.js';
import type { Connector, Holder } from './index.js';

export interface RestConfig { endpoint: string; authHeader?: string; healthCheckIdentifier?: string; }

export function loadRestConnector(config: RestConfig, pseudonymSecret: string): Connector {
  if (!config.endpoint.includes('{id}')) throw new Error('REST endpoint must contain {id}');
  const parsed = new URL(config.endpoint.replace('{id}', 'probe'));
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error('Invalid REST endpoint URL');
  const fetchRecord = async (identifier: string): Promise<Holder | null> => {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (config.authHeader) headers.Authorization = config.authHeader;
    const res = await fetch(config.endpoint.replaceAll('{id}', encodeURIComponent(identifier)), { headers, signal: AbortSignal.timeout(10000), redirect: 'error' });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error('REST source returned an unsuccessful response');
    const row: unknown = await res.json();
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('REST source must return one holder object');
    return row as Holder;
  };
  const probe = async () => {
    if (!config.healthCheckIdentifier) throw new Error('REST schema and setup validation require healthCheckIdentifier for an existing holder');
    const row = await fetchRecord(config.healthCheckIdentifier);
    if (!row) throw new Error('REST health check holder was not found');
    return row;
  };
  return {
    lookup: async identifier => {
      const row = await fetchRecord(identifier);
      if (!row) return null;
      const id = String(row.id ?? identifier);
      return { ...row, id, _lookupIdentifier: identifier, defaultPassword: deriveHolderPassword(id, pseudonymSecret), _source: 'rest' };
    },
    getSchema: async () => Object.keys(await probe()),
    healthCheck: async () => { await probe(); },
  };
}
