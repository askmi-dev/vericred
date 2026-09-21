import type { VeriCredConfig } from '../config/types.js';
import { loadConfig, ConfigConflictError } from '../config/loader.js';
import { loadSecrets } from '../config/secrets.js';
import { loadJsonConnector } from './json.js';
import { loadPostgresConnector } from './postgres.js';
import { loadMySQLConnector } from './mysql.js';
import { loadRestConnector } from './rest.js';
import { loadCSVConnector } from './csv.js';
import { loadManualConnector } from './manual.js';

export type Holder = Record<string, unknown> & { _lookupIdentifier?: string };
export type Lookup = (id: string) => Promise<Holder | null> | Holder | null;
export interface Connector {
  lookup: Lookup;
  /** Reject an offer lookup if its source or configuration changes while awaiting I/O. */
  lookupForConfig?: (id: string, expectedConfig: VeriCredConfig) => Promise<Holder | null>;
  getSchema: () => Promise<string[]> | string[];
  list?: (options?: { limit?: number; offset?: number }) => Promise<Holder[]> | Holder[];
  healthCheck?: () => Promise<void> | void;
  close?: () => Promise<void> | void;
  activate?: (config: VeriCredConfig, candidate: Connector) => void;
}
export class ListingUnavailableError extends Error {
  constructor() { super('This source supports identifier lookup only; provide an identifier to retrieve a holder.'); }
}
export function buildConnector(config: VeriCredConfig): Connector {
  const ds = config.dataSource;
  if (ds.type === 'json') return loadJsonConnector(ds.path ?? './data/holders.json');
  const { pseudonymSecret } = loadSecrets();
  switch (ds.type) {
    case 'postgres':
      if (!ds.connectionString) throw new Error('Postgres requires connectionString');
      return loadPostgresConnector({ connectionString: ds.connectionString, table: ds.table ?? 'users', identifierColumn: ds.identifierColumn ?? 'email' }, pseudonymSecret);
    case 'mysql':
      if (!ds.connectionString) throw new Error('MySQL requires connectionString');
      return loadMySQLConnector({ connectionString: ds.connectionString, table: ds.table ?? 'users', identifierColumn: ds.identifierColumn ?? 'email' }, pseudonymSecret);
    case 'rest':
      if (!ds.endpoint) throw new Error('REST requires endpoint');
      return loadRestConnector({ endpoint: ds.endpoint, authHeader: ds.authHeader, healthCheckIdentifier: ds.healthCheckIdentifier }, pseudonymSecret);
    case 'csv': return loadCSVConnector({ path: ds.path ?? './data/holders.csv', identifierColumn: ds.identifierColumn ?? 'email' }, pseudonymSecret);
    case 'manual': return loadManualConnector({ path: ds.path }, pseudonymSecret);
    default: throw new Error('Unknown dataSource.type');
  }
}

/** Switch new requests immediately; release old pools only after their in-flight work finishes. */
export function liveConnector(readConfig = loadConfig, build = buildConnector): Connector {
  type Slot = { key: string; connector: Connector; users: number; retired: boolean; closing: boolean; drained: Promise<void>; finish: () => void };
  const slots = new Set<Slot>();
  let current: Slot | undefined;
  let closed = false;
  const cleanup = (slot: Slot) => {
    if (slot.retired && !slot.users && !slot.closing) {
      slot.closing = true;
      void Promise.resolve().then(() => slot.connector.close?.()).catch(() => console.error('[connector] Failed to close retired source')).finally(() => { slots.delete(slot); slot.finish(); });
    }
  };
  const activate = (config: VeriCredConfig, connector: Connector) => {
    if (closed) throw new Error('Connector is closed');
    const previous = current;
    let finish!: () => void;
    const drained = new Promise<void>(resolve => { finish = resolve; });
    current = { key: JSON.stringify(config.dataSource), connector, users: 0, retired: false, closing: false, drained, finish };
    slots.add(current);
    if (previous) { previous.retired = true; cleanup(previous); }
  };
  const run = async <T>(operation: (connector: Connector) => T | Promise<T>): Promise<T> => {
    if (closed) throw new Error('Connector is closed');
    const config = readConfig();
    if (!current || current.key !== JSON.stringify(config.dataSource)) activate(config, build(config));
    const slot = current!;
    slot.users++;
    try { return await operation(slot.connector); }
    finally { slot.users--; cleanup(slot); }
  };
  return {
    lookup: id => run(connector => connector.lookup(id)),
    lookupForConfig: async (id, expectedConfig) => {
      const expected = JSON.stringify(expectedConfig);
      if (JSON.stringify(readConfig()) !== expected) throw new ConfigConflictError();
      const holder = await run(connector => connector.lookup(id));
      if (JSON.stringify(readConfig()) !== expected) throw new ConfigConflictError();
      return holder;
    },
    getSchema: () => run(connector => connector.getSchema()),
    list: options => run(connector => { if (!connector.list) throw new ListingUnavailableError(); return connector.list(options); }),
    healthCheck: () => run(async connector => { if (connector.healthCheck) await connector.healthCheck(); else await connector.getSchema(); }),
    activate,
    close: async () => {
      closed = true;
      const draining = [...slots];
      for (const slot of draining) { slot.retired = true; cleanup(slot); }
      await Promise.all(draining.map(slot => slot.drained));
    },
  };
}

