/**
 * CSV connector — queries holder data from a local CSV file.
 * Automatically parses header rows and matches by the configured identifier column.
 */
import fs from 'fs';
import path from 'path';
import { deriveHolderPassword } from '../config/secrets.js';
import type { Connector } from './index.js';

export interface CSVConfig {
  path: string;
  identifierColumn: string; // e.g. "email" or "student_id"
}

/**
 * Robust CSV parser that handles standard quoted cells, escape sequences, and commas.
 */
export function parseCSV(content: string): Record<string, string>[] {
  const lines: string[][] = [];
  let currentRow: string[] = [];
  let currentField = '';
  let inQuotes = false;

  for (let i = 0; i < content.length; i++) {
    const char = content[i];
    const nextChar = content[i + 1];

    if (inQuotes) {
      if (char === '"') {
        if (nextChar === '"') {
          // Escaped double quote
          currentField += '"';
          i++; // Skip the next quote
        } else {
          // Closing quote
          inQuotes = false;
        }
      } else {
        currentField += char;
      }
    } else {
      if (char === '"') {
        inQuotes = true;
      } else if (char === ',') {
        currentRow.push(currentField.trim());
        currentField = '';
      } else if (char === '\n' || char === '\r') {
        currentRow.push(currentField.trim());
        if (currentRow.some(cell => cell !== '') || currentField !== '') {
          lines.push(currentRow);
        }
        currentRow = [];
        currentField = '';
        if (char === '\r' && nextChar === '\n') {
          i++; // Skip LF if it's CRLF
        }
      } else {
        currentField += char;
      }
    }
  }

  // Push final field if any
  if (currentRow.length > 0 || currentField !== '') {
    currentRow.push(currentField.trim());
    lines.push(currentRow);
  }

  if (lines.length === 0) return [];

  const headers = lines[0].map(h => h.trim());
  const records: Record<string, string>[] = [];

  for (let i = 1; i < lines.length; i++) {
    const row = lines[i];
    const record: Record<string, string> = {};
    for (let j = 0; j < headers.length; j++) {
      record[headers[j].toLowerCase()] = row[j] ?? '';
    }
    records.push(record);
  }

  return records;
}

export function loadCSVConnector(
  config: CSVConfig,
  pseudonymSecret: string
): Connector {
  const resolvedPath = path.resolve(config.path);

  const getRecords = () => {
    if (!fs.existsSync(resolvedPath)) return [];
    const content = fs.readFileSync(resolvedPath, 'utf8');
    return parseCSV(content);
  };

  return {
    lookup: (identifier: string) => {
      try {
        if (!fs.existsSync(resolvedPath)) {
          console.error(`[connector:csv] File not found at: ${resolvedPath}`);
          return null;
        }
        const records = getRecords();
        const targetCol = config.identifierColumn.toLowerCase();
        const targetVal = identifier.toLowerCase();

        const matched = records.find(r => String(r[targetCol] ?? '').toLowerCase() === targetVal);
        if (!matched) return null;

        const id = String(matched['id'] ?? matched[targetCol] ?? identifier);

        // Convert values to actual JS types if they look like numbers or booleans
        const typedRecord: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(matched)) {
          if (v === 'true') typedRecord[k] = true;
          else if (v === 'false') typedRecord[k] = false;
          else if (!isNaN(Number(v)) && v !== '') typedRecord[k] = Number(v);
          else typedRecord[k] = v;
        }

        return {
          ...typedRecord,
          id,
          defaultPassword: deriveHolderPassword(id, pseudonymSecret),
          _source: 'csv',
        };
      } catch (err) {
        console.error('[connector:csv] Query failed:', err);
        return null;
      }
    },
    getSchema: () => {
      if (!fs.existsSync(resolvedPath)) return ['id', 'email', 'firstName', 'lastName'];
      const content = fs.readFileSync(resolvedPath, 'utf8');
      const lines = content.split(/\r?\n/);
      if (lines.length === 0) return [];
      return lines[0].split(',').map(h => h.trim().replace(/^"|"$/g, ''));
    }
  };
}
