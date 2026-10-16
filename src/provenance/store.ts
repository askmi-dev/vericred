/**
 * JSONL provenance store — Art. 6a audit evidence (#26).
 *
 * Design: append-only JSON Lines at ${DATA_DIR}/provenance/issuance.jsonl.
 * Persistence is best-effort (mirrors runtime.ts): a failure to write the
 * audit record must never block or fail a credential issuance. Errors are
 * logged loudly instead.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'fs';
import { randomUUID } from 'crypto';
import { provenanceRecordSchema, type ProvenanceRecord } from './types.js';

// Resolved lazily so tests (and deployments) can point DATA_DIR per
// environment, matching how other stores read it.
function provenancePath(): string {
  const dataDir = process.env.DATA_DIR ?? '.';
  return `${dataDir}/provenance/issuance.jsonl`;
}

/**
 * Persist one provenance record. Best-effort: returns the record on
 * success, null on failure (issuance must proceed either way).
 */
export function appendProvenanceRecord(
  record: Omit<ProvenanceRecord, 'provenanceId'>
): ProvenanceRecord | null {
  const full: ProvenanceRecord = { provenanceId: randomUUID(), ...record };
  // Fail closed on schema violations *before* writing garbage to the log.
  const parsed = provenanceRecordSchema.safeParse(full);
  if (!parsed.success) {
    console.error('[provenance] Record failed schema validation, not persisted:', parsed.error.message);
    return null;
  }
  try {
    const path = provenancePath();
    mkdirSync(path.slice(0, path.lastIndexOf('/')), { recursive: true });
    appendFileSync(path, JSON.stringify(parsed.data) + '\n', 'utf8');
    return parsed.data;
  } catch (err) {
    console.error('[provenance] Could not persist provenance record (issuance unaffected):', (err as Error).message);
    return null;
  }
}

/** Test/inspection helper: read all records from the active store. */
export function readProvenanceRecords(): ProvenanceRecord[] {
  try {
    const path = provenancePath();
    if (!existsSync(path)) return [];
    return readFileSync(path, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(line => JSON.parse(line) as ProvenanceRecord);
  } catch {
    return [];
  }
}
