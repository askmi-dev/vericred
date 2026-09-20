import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadCSVConnector, parseCSV } from '../csv.js';
import fs from 'fs';
vi.mock('fs', () => ({ default: { existsSync: vi.fn(), readFileSync: vi.fn() } }));
describe('CSV source', () => {
  beforeEach(() => vi.clearAllMocks());
  it('handles quoted delimiters and escaped quotes', () => {
    expect(parseCSV('id,name,quote\n001,"Doe, Jane","She said ""Hello"""')).toEqual([{ id: '001', name: 'Doe, Jane', quote: 'She said "Hello"' }]);
  });
  it('rejects malformed rows and duplicate or unsafe headers', () => {
    expect(() => parseCSV('id,id\n1,2')).toThrow('unique');
    expect(() => parseCSV('id,name\n1')).toThrow('number of fields');
    expect(() => parseCSV('id,name\n1,"Jane')).toThrow('unterminated');
    expect(() => parseCSV('__proto__,name\n1,Jane')).toThrow('unique');
  });
  it('preserves numeric-looking identifiers and values without guessing types', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue('id,email,postalCode,isActive\n0001,A@test.com,01234,true');
    const connector = loadCSVConnector({ path: './holders.csv', identifierColumn: 'email' }, 'secret');
    expect(await connector.lookup('a@test.com')).toMatchObject({ id: '0001', postalcode: '01234', isactive: 'true' });
    expect(await connector.getSchema()).toEqual(['id', 'email', 'postalcode', 'isactive']);
    expect(await connector.list!()).toHaveLength(1);
  });
  it('distinguishes missing files from unknown holders', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(false);
    const connector = loadCSVConnector({ path: './missing.csv', identifierColumn: 'email' }, 'secret');
    expect(() => connector.lookup('a@test.com')).toThrow('does not exist');
    expect(() => connector.getSchema()).toThrow('does not exist');
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue('id,email\n0001,a@test.com');
    expect(await connector.lookup('unknown')).toBeNull();
  });

  it('lists a source lookup key without replacing a leading-zero stable id', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue('id,email,name\n0001,holder@example.org,Holder');
    const source = loadCSVConnector({ path: './holders.csv', identifierColumn: 'email' }, 'secret');
    const [holder] = await source.list!();
    expect(holder.id).toBe('0001');
    expect(holder._lookupIdentifier).toBe('holder@example.org');
    expect(await source.lookup(holder._lookupIdentifier!)).toMatchObject({ id: '0001', name: 'Holder' });
  });
});
