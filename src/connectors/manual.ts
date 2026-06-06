/**
 * Manual connector — registers and queries manual holder data from a JSON file.
 * Perfect for small organizations running self-hosted gateways with manual entry.
 */
import fs from 'fs';
import path from 'path';
import { deriveHolderPassword } from '../config/secrets.js';

export interface ManualConfig {
  path?: string; // defaults to ./data/manual_holders.json
}

export class ManualRegistry {
  private filePath: string;
  private holders: Record<string, unknown>[] = [];

  constructor(filePath: string) {
    this.filePath = path.resolve(filePath);
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const data = fs.readFileSync(this.filePath, 'utf8');
        this.holders = JSON.parse(data) as Record<string, unknown>[];
      } else {
        // Initialize empty or with seeds
        const dir = path.dirname(this.filePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        this.holders = [];
        this.save();
      }
    } catch (err) {
      console.error('[connector:manual] Failed to load manual database:', err);
      this.holders = [];
    }
  }

  public save() {
    try {
      fs.writeFileSync(this.filePath, JSON.stringify(this.holders, null, 2), 'utf8');
    } catch (err) {
      console.error('[connector:manual] Failed to save manual database:', err);
    }
  }

  public find(identifier: string): Record<string, unknown> | null {
    const idLower = identifier.toLowerCase();
    const found = this.holders.find(h => {
      const email = String(h['email'] ?? '').toLowerCase();
      const id = String(h['id'] ?? '').toLowerCase();
      const studentId = String(h['studentId'] ?? h['student_id'] ?? '').toLowerCase();
      return email === idLower || id === idLower || studentId === idLower;
    });
    return found ? { ...found } : null;
  }

  public add(record: Record<string, unknown>) {
    if (!record['id']) {
      throw new Error('[connector:manual] Record must have a unique "id" field');
    }
    const existingIndex = this.holders.findIndex(h => h['id'] === record['id']);
    if (existingIndex >= 0) {
      this.holders[existingIndex] = record;
    } else {
      this.holders.push(record);
    }
    this.save();
  }

  public list(): Record<string, unknown>[] {
    return [...this.holders];
  }

  public remove(id: string) {
    this.holders = this.holders.filter(h => h['id'] !== id);
    this.save();
  }
}

let activeRegistry: ManualRegistry | null = null;

export function getManualRegistry(filePath = './data/manual_holders.json'): ManualRegistry {
  if (!activeRegistry) {
    activeRegistry = new ManualRegistry(filePath);
  }
  return activeRegistry;
}

import type { Connector } from './index.js';

export function loadManualConnector(
  config: ManualConfig,
  pseudonymSecret: string
): Connector {
  const filePath = config.path ?? './data/manual_holders.json';
  const registry = getManualRegistry(filePath);

  return {
    lookup: (identifier: string) => {
      const matched = registry.find(identifier);
      if (!matched) return null;

      const id = String(matched['id'] ?? identifier);
      return {
        ...matched,
        id,
        defaultPassword: deriveHolderPassword(id, pseudonymSecret),
        _source: 'manual',
      };
    },
    getSchema: () => {
      const list = registry.list();
      if (list.length === 0) return ['id', 'email', 'firstName', 'lastName'];
      return Object.keys(list[0]);
    }
  };
}
