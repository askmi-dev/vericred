import fs from 'fs';
import path from 'node:path';
import { deriveHolderPassword } from '../config/secrets.js';
import type { Connector } from './index.js';
import { pageBounds } from './sql.js';
export interface CSVConfig { path: string; identifierColumn: string; }

function parseRows(content: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], field = '', quoted = false;
  for (let i = 0; i < content.length; i++) {
    const char = content[i];
    if (quoted) {
      if (char === '"' && content[i + 1] === '"') { field += '"'; i++; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') { row.push(field.trim()); field = ''; }
    else if (char === '\n' || char === '\r') {
      row.push(field.trim());
      if (row.some(Boolean)) rows.push(row);
      row = []; field = '';
      if (char === '\r' && content[i + 1] === '\n') i++;
    } else field += char;
  }
  if (quoted) throw new Error('CSV contains an unterminated quoted field');
  if (row.length || field) { row.push(field.trim()); rows.push(row); }
  return rows;
}
function headersOf(rows: string[][]): string[] {
  const headers = (rows[0] ?? []).map(header => header.toLowerCase());
  if (headers.some(header => !header || ['__proto__', 'constructor', 'prototype'].includes(header)) || new Set(headers).size !== headers.length) throw new Error('CSV headers must be unique and nonempty');
  return headers;
}
export function parseCSV(content: string): Record<string, string>[] {
  const rows = parseRows(content);
  const headers = headersOf(rows);
  return rows.slice(1).map(row => {
    if (row.length !== headers.length) throw new Error('CSV row has a different number of fields than its header');
    return Object.fromEntries(headers.map((header, i) => [header, row[i]]));
  });
}
export function loadCSVConnector(config: CSVConfig, pseudonymSecret: string): Connector {
  const resolvedPath = path.resolve(config.path);
  const content = () => { if (!fs.existsSync(resolvedPath)) throw new Error('CSV source file does not exist'); return fs.readFileSync(resolvedPath, 'utf8'); };
  const read = () => parseCSV(content());
  const decorate = (row: Record<string, string>) => {
    const id = String(row.id ?? row[config.identifierColumn.toLowerCase()] ?? '');
    return { ...row, id, _lookupIdentifier: row[config.identifierColumn.toLowerCase()] ?? '', defaultPassword: deriveHolderPassword(id, pseudonymSecret), _source: 'csv' };
  };
  const getSchema = () => headersOf(parseRows(content()));
  return {
    lookup: identifier => {
      const row = read().find(record => String(record[config.identifierColumn.toLowerCase()] ?? '').toLowerCase() === identifier.toLowerCase());
      return row ? decorate(row) : null;
    },
    list: options => { const { limit, offset } = pageBounds(options); return read().slice(offset, offset + limit).map(decorate); },
    getSchema,
    healthCheck: () => { if (!getSchema().includes(config.identifierColumn.toLowerCase())) throw new Error('CSV identifier column does not exist'); read(); },
  };
}
