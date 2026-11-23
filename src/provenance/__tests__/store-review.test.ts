/**
 * #36 review follow-up — provenance privacy and reader-state tests.
 *
 * Covers the review findings on the Art. 6a provenance branch:
 *  1. identifier hashes are keyed (HMAC), not plain unsalted SHA-256 —
 *     a leaked log cannot be joined against externally computed
 *     SHA-256 sets without the key;
 *  2. sourceRef never persists credentials, query strings or fragments
 *     from configured endpoints/paths;
 *  3. the reader distinguishes absent, per-line corrupt and unavailable
 *     states — a corrupt line no longer hides valid history.
 * Honest limit recorded here: a keyed hash is a stable pseudonym, not
 * anonymity; anyone holding PROVENANCE_HASH_KEY can test guessed
 * identifiers and join records.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, rmSync, writeFileSync, chmodSync } from 'fs';
import { appendProvenanceRecord, readProvenance, readProvenanceRecords } from '../store.js';
import { hashIdentifier, sanitizeSourceRef, type ProvenanceRecord } from '../types.js';

const TEMP = './src/provenance/__tests__/temp-review';

function makeRecord(overrides: Partial<ProvenanceRecord> = {}): Omit<ProvenanceRecord, 'provenanceId'> {
  return {
    credentialId: 'urn:uuid:11111111-2222-3333-4444-555555555555',
    credentialType: 'EmployeeCredential',
    source: { connectorType: 'postgres', sourceRef: 'table:users' },
    lookup: { identifierHash: hashIdentifier('review-holder@example.com'), at: new Date().toISOString() },
    verification: { mode: 'authoritative-source' },
    consentGate: { used: false, claimsSnapshot: false },
    issuedAt: new Date().toISOString(),
    issuerDid: 'did:web:example.com',
    ...overrides,
  };
}

describe('#36 review: keyed identifier pseudonym', () => {
  beforeEach(() => { process.env['PROVENANCE_HASH_KEY'] = 'test-key-1'; });
  afterEach(() => { delete process.env['PROVENANCE_HASH_KEY']; });

  it('is not the plain unsalted SHA-256 of the identifier', async () => {
    const { createHash } = await import('crypto');
    const plain = createHash('sha256').update('alice@example.com').digest('hex');
    expect(hashIdentifier('alice@example.com')).not.toBe(plain);
  });

  it('changes when the key changes (key rotation breaks joins, by design)', () => {
    const h1 = hashIdentifier('bob@example.com');
    process.env['PROVENANCE_HASH_KEY'] = 'test-key-2';
    const h2 = hashIdentifier('bob@example.com');
    expect(h1).not.toBe(h2);
  });

  it('is deterministic for the same key (stable join within a deployment)', () => {
    expect(hashIdentifier('carol@example.com')).toBe(hashIdentifier('carol@example.com'));
  });
});

describe('#36 review: sourceRef sanitization', () => {
  it('strips credentials, query strings and fragments from URL refs', () => {
    expect(sanitizeSourceRef('https://api.example.com:8443/v2/users?token=sekret&x=1#frag'))
      .toBe('https://api.example.com:8443/v2/users');
    expect(sanitizeSourceRef('https://user:pass@api.example.com/users'))
      .toBe('https://api.example.com/users');
  });

  it('keeps opaque non-URL refs like table:users untouched', () => {
    expect(sanitizeSourceRef('table:users')).toBe('table:users');
    expect(sanitizeSourceRef('data/holders.json')).toBe('data/holders.json');
  });

  it('redacts non-URL refs that look like they carry credentials', () => {
    expect(sanitizeSourceRef('postgres://admin:pw@db.internal:5432/users')).toBe('redacted');
  });

  it('sanitized refs never leak into the persisted log', () => {
    const TEMP2 = './src/provenance/__tests__/temp-sanitize';
    process.env['DATA_DIR'] = TEMP2;
    rmSync(TEMP2, { recursive: true, force: true });
    try {
      const rec = appendProvenanceRecord(makeRecord({
        source: { connectorType: 'rest', sourceRef: sanitizeSourceRef('https://user:secret@api.example.com/users?token=abc') },
      }));
      expect(rec).not.toBeNull();
      const persisted = JSON.stringify(readProvenanceRecords());
      expect(persisted).not.toContain('secret');
      expect(persisted).not.toContain('token=abc');
      expect(persisted).toContain('api.example.com/users');
    } finally {
      rmSync(TEMP2, { recursive: true, force: true });
      delete process.env['DATA_DIR'];
    }
  });
});

describe('#36 review: reader distinguishes absent, corrupt, unavailable', () => {
  const FILE = `${TEMP}/provenance/issuance.jsonl`;

  beforeEach(() => {
    process.env['DATA_DIR'] = TEMP;
    rmSync(TEMP, { recursive: true, force: true });
    mkdirSync(TEMP, { recursive: true });
  });
  afterEach(() => {
    chmodSync(TEMP, 0o700);
    rmSync(TEMP, { recursive: true, force: true });
    delete process.env['DATA_DIR'];
  });

  it('reports absent when no log exists', () => {
    const result = readProvenance();
    expect(result.absent).toBe(true);
    expect(result.corrupt).toBe(0);
    expect(result.unavailable).toBe(false);
    expect(result.records.length).toBe(0);
  });

  it('a corrupt line does not hide the valid records around it', () => {
    const good1 = appendProvenanceRecord(makeRecord());
    writeFileSync(FILE, JSON.stringify(good1) + '\n{corrupt line\n', 'utf8');
    const good2 = appendProvenanceRecord(makeRecord());
    expect(good2).not.toBeNull();

    const result = readProvenance();
    expect(result.absent).toBe(false);
    expect(result.corrupt).toBe(1);
    expect(result.records.length).toBe(2);
  });

  it('reports unavailable when the file cannot be read', () => {
    mkdirSync(`${TEMP}/provenance`, { recursive: true });
    writeFileSync(FILE, 'x', 'utf8');
    chmodSync(FILE, 0o000);
    const result = readProvenance();
    expect(result.unavailable).toBe(true);
    expect(result.records.length).toBe(0);
    chmodSync(FILE, 0o600);
  });
});
