import { existsSync, readFileSync } from 'node:fs';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { loadSecrets } from '../config/secrets.js';
import { atomicWrite } from './atomic.js';

/** Durable state for a single writer, protected by the server's DATA_DIR lease. */
export class EncryptedMap<T> {
  constructor(private readonly name: string) {}
  private path() { return join(process.env.DATA_DIR ?? './data', this.name + '.encrypted.json'); }
  private key() { return createHash('sha256').update('vericred:' + this.name + ':' + loadSecrets().pseudonymSecret).digest(); }
  private read(): Map<string, T> {
    if (!existsSync(this.path())) return new Map();
    const data = JSON.parse(readFileSync(this.path(), 'utf8'));
    if (data.version !== 1) throw new Error('Unsupported state format');
    const cipher = createDecipheriv('aes-256-gcm', this.key(), Buffer.from(data.iv, 'hex'));
    cipher.setAuthTag(Buffer.from(data.tag, 'hex'));
    return new Map(JSON.parse(Buffer.concat([cipher.update(Buffer.from(data.content, 'hex')), cipher.final()]).toString('utf8')));
  }
  private save(map: Map<string, T>) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key(), iv);
    const content = Buffer.concat([cipher.update(JSON.stringify([...map])), cipher.final()]);
    atomicWrite(this.path(), JSON.stringify({ version: 1, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), content: content.toString('hex') }));
  }
  get(key: string) { return this.read().get(key); }
  has(key: string) { return this.read().has(key); }
  set(key: string, value: T) { const map = this.read(); map.set(key, value); this.save(map); return this; }
  delete(key: string) { const map = this.read(); const removed = map.delete(key); if (removed) this.save(map); return removed; }
  [Symbol.iterator]() { return this.read()[Symbol.iterator](); }
}
