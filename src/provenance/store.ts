/**
 * JSONL provenance store — Art. 6a audit evidence (#26).
 *
 * Design: append-only JSON Lines at ${DATA_DIR}/provenance/issuance.jsonl.
 * Persistence is best-effort (mirrors runtime.ts): a failure to write the
 * audit record must never block or fail a credential issuance. Errors are
 * logged loudly instead — and the issuance path writes the record BEFORE
 * responding, so a holder-visible success implies the append was
 * attempted; a null return is logged as an incomplete audit trail.
 *
 * Reader semantics (#36 review): absent, corrupt and unavailable are
 * distinct states. A single corrupt line must not silently hide the
 * valid history around it: valid lines are returned, corrupt lines are
 * reported separately.
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

export interface ReadResult {
  /** Present, schema-valid records. */
  records: ProvenanceRecord[];
  /** Lines that exist but failed parse or schema validation. */
  corrupt: number;
  /** No file exists at the expected path. */
  absent: boolean;
  /** The file exists but could not be read at all. */
  unavailable: boolean;
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

/**
 * Read all records from the active store, distinguishing absent,
 * corrupt-per-line and unavailable states. Corrupt lines never mask
 * valid ones.
 */
export function readProvenance(): ReadResult {
  const path = provenancePath();
  if (!existsSync(path)) return { records: [], corrupt: 0, absent: true, unavailable: false };
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    console.error('[provenance] Store unreadable:', (err as Error).message);
    return { records: [], corrupt: 0, absent: false, unavailable: true };
  }
  const records: ProvenanceRecord[] = [];
  let corrupt = 0;
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      const candidate = JSON.parse(line) as ProvenanceRecord;
      const parsed = provenanceRecordSchema.safeParse(candidate);
      if (parsed.success) records.push(parsed.data);
      else corrupt++;
    } catch {
      corrupt++;
    }
  }
  return { records, corrupt, absent: false, unavailable: false };
}

/**
 * Back-compat helper: valid records only. Callers that need to see
 * corrupt/unavailable states must use readProvenance() instead.
 */
export function readProvenanceRecords(): ProvenanceRecord[] {
  return readProvenance().records;
}
