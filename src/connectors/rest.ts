/**
 * REST API connector — calls an existing org endpoint to fetch holder data by identifier.
 * Config: { endpoint: "https://api.uni.example.com/students/{id}", authHeader: "Bearer TOKEN" }
 */
import { deriveHolderPassword } from '../config/secrets.js';

export interface RestConfig {
  endpoint: string;    // use {id} as placeholder, e.g. https://api.example.com/users/{id}
  authHeader?: string; // optional Authorization header value
}

export function loadRestConnector(
  config: RestConfig,
  pseudonymSecret: string
): (identifier: string) => Promise<Record<string, unknown> | null> {
  return async (identifier: string) => {
    try {
      const url = config.endpoint.replace('{id}', encodeURIComponent(identifier));
      const headers: Record<string, string> = { 'Accept': 'application/json' };
      if (config.authHeader) headers['Authorization'] = config.authHeader;

      const res = await fetch(url, { headers });
      if (!res.ok) return null;

      const row = await res.json() as Record<string, unknown>;
      const id = String(row['id'] ?? identifier);
      return { ...row, id, defaultPassword: deriveHolderPassword(id, pseudonymSecret), _source: 'rest' };
    } catch (err) {
      console.error('[connector:rest] Request failed:', err);
      return null;
    }
  };
}
