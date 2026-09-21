import { readFileSync } from 'node:fs';
import type { Connector, Holder } from './index.js';
import { pageBounds } from './sql.js';

export function readHolderFile(path: string): Holder[] {
  const data: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(data) || data.some(row => !row || typeof row !== 'object' || Array.isArray(row))) throw new Error('Holder source must contain an array of objects');
  return data as Holder[];
}
export function loadJsonConnector(path: string): Connector {
  const read = () => readHolderFile(path);
  const identifierOf = (row: Holder) => [row.id, row.email, row.studentId].find(value => value !== undefined && value !== null && String(value) !== '');
  const decorate = (row: Holder): Holder => ({ ...row, _lookupIdentifier: String(identifierOf(row) ?? '') });
  return {
    lookup: identifier => {
      const row = read().find(record => [record.id, record.email, record.studentId].some(value => value !== undefined && value !== null && String(value) === identifier));
      return row ? decorate(row) : null;
    },
    list: options => { const { limit, offset } = pageBounds(options); return read().slice(offset, offset + limit).map(decorate); },
    getSchema: () => [...new Set(read().flatMap(Object.keys))],
    healthCheck: () => { read(); },
  };
}
