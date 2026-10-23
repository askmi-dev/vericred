/**
 * #26 — Provenance module tests (Art. 6a audit evidence).
 *
 * PR-1 scope: the module itself, independent of the issuance wiring.
 *  1. Round-trip: valid record persists and reads back
 *  2. identifierHash is a sha256 hex — raw identifiers must never appear
 *  3. Schema rejects malformed records (fail closed before write)
 *  4. Store failure (unwritable path) returns null, never throws
 *  5. Consistency: same identifier always hashes identically
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdirSync, rmSync, writeFileSync, chmodSync } from 'fs';
import { appendProvenanceRecord, readProvenanceRecords } from '../store.js';
import { hashIdentifier, provenanceRecordSchema, type ProvenanceRecord } from '../types.js';

const TEMP = './src/provenance/__tests__/temp-store';

function makeRecord(overrides: Partial<ProvenanceRecord> = {}): Omit<ProvenanceRecord, 'provenanceId'> {
  return {
    credentialId: 'urn:uuid:' + '11111111-2222-3333-4444-555555555555',
    credentialType: 'EmployeeCredential',
    source: { connectorType: 'postgres', sourceRef: 'table:users' },
    lookup: { identifierHash: hashIdentifier('john.doe@example.com'), at: new Date().toISOString() },
    verification: { mode: 'authoritative-source' },
    consentGate: { used: false, claimsSnapshot: false },
    issuedAt: new Date().toISOString(),
    issuerDid: 'did:web:example.com',
    ...overrides,
  };
}

describe('#26 provenance module', () => {
  beforeEach(() => {
    process.env['DATA_DIR'] = TEMP;
    rmSync(TEMP, { recursive: true, force: true });
    mkdirSync(TEMP, { recursive: true });
  });
  afterEach(() => {
    rmSync(TEMP, { recursive: true, force: true });
    delete process.env['DATA_DIR'];
  });

  it('persists a valid record and reads it back unchanged', () => {
    const rec = appendProvenanceRecord(makeRecord());
    expect(rec).not.toBeNull();
    const all = readProvenanceRecords();
    expect(all.length).toBe(1);
    expect(all[0]).toMatchObject({ credentialType: 'EmployeeCredential', provenanceId: rec!.provenanceId });
  });

  it('never stores the raw identifier — only its keyed-hash hex', () => {
    const raw = 'jane.private@example.com';
    appendProvenanceRecord(makeRecord({ lookup: { identifierHash: hashIdentifier(raw), at: new Date().toISOString() } }));
    const persisted = JSON.stringify(readProvenanceRecords());
    expect(persisted).not.toContain(raw);
    expect(persisted).not.toContain('jane.private');
    expect(hashIdentifier(raw)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hashes deterministically — same identifier, same hash', () => {
    expect(hashIdentifier('a@b.c')).toBe(hashIdentifier('a@b.c'));
    expect(hashIdentifier('a@b.c')).not.toBe(hashIdentifier('b@b.c'));
  });

  it('rejects malformed records before writing (fail closed on schema)', () => {
    const bad = makeRecord();
    (bad as unknown as Record<string, unknown>).credentialId = 'not-a-urn';
    expect(appendProvenanceRecord(bad)).toBeNull();
    expect(readProvenanceRecords().length).toBe(0);
    expect(provenanceRecordSchema.safeParse(bad).success).toBe(false);
  });

  it('returns null instead of throwing when the store is unwritable', () => {
    // DATA_DIR pointing at a read-only location
    const blocked = `${TEMP}/readonly`;
    mkdirSync(blocked, { recursive: true });
    writeFileSync(`${blocked}/.keep`, '');
    chmodSync(blocked, 0o500); // r-x : no write
    process.env['DATA_DIR'] = blocked;
    try {
      expect(appendProvenanceRecord(makeRecord())).toBeNull();
    } finally {
      process.env['DATA_DIR'] = TEMP;
      chmodSync(blocked, 0o700);
    }
  });
});
