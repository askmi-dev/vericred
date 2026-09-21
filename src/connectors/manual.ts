import fs from 'fs';
import path from 'node:path';
import { deriveHolderPassword } from '../config/secrets.js';
import { atomicWrite } from '../storage/atomic.js';
import type { Connector, Holder } from './index.js';
import { pageBounds } from './sql.js';
export interface ManualConfig { path?: string; }

export class ManualRegistry {
  private filePath: string;
  private holders: Holder[] = [];
  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
    if (fs.existsSync(this.filePath)) {
      const data: unknown = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      if (!Array.isArray(data) || data.some(row => !row || typeof row !== 'object' || Array.isArray(row))) throw new Error('Manual source must contain an array of objects');
      this.holders = data as Holder[];
    }
  }
  public save() { atomicWrite(this.filePath, JSON.stringify(this.holders, null, 2)); }
  public find(identifier: string): Holder | null {
    const target = identifier.toLowerCase();
    const found = this.holders.find(holder => ['email', 'id', 'studentId', 'student_id'].some(key => String(holder[key] ?? '').toLowerCase() === target));
    return found ? { ...found } : null;
  }
  public add(record: Holder) {
    if (!record.id) throw new Error('Record must have a unique id');
    const index = this.holders.findIndex(holder => holder.id === record.id);
    if (index >= 0) this.holders[index] = { ...record }; else this.holders.push({ ...record });
    this.save();
  }
  public list(): Holder[] { return this.holders.map(holder => ({ ...holder })); }
  public remove(id: string) { this.holders = this.holders.filter(holder => holder.id !== id); this.save(); }
}
export function getManualRegistry(filePath = './data/manual_holders.json'): ManualRegistry { return new ManualRegistry(filePath); }
export function loadManualConnector(config: ManualConfig, pseudonymSecret: string): Connector {
  const registry = () => getManualRegistry(config.path ?? './data/manual_holders.json');
  const decorate = (row: Holder) => {
    const id = String(row.id ?? '');
    return { ...row, id, _lookupIdentifier: id, defaultPassword: deriveHolderPassword(id, pseudonymSecret), _source: 'manual' };
  };
  return {
    lookup: identifier => { const row = registry().find(identifier); return row ? decorate(row) : null; },
    list: options => { const { limit, offset } = pageBounds(options); return registry().list().slice(offset, offset + limit).map(decorate); },
    getSchema: () => [...new Set(registry().list().flatMap(Object.keys))],
    healthCheck: () => { registry(); },
  };
}
