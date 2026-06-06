import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadCSVConnector, parseCSV } from '../csv.js';
import fs from 'fs';

vi.mock('fs', () => {
  return {
    default: {
      existsSync: vi.fn(),
      readFileSync: vi.fn(),
    }
  };
});

describe('CSV Connector & Parser', () => {
  const pseudonymSecret = 'test_pseudonym_secret_32_bytes_long_!!!';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('parseCSV function', () => {
    it('parses standard unquoted CSV content correctly', () => {
      const csv = `id,email,name,isStudent
123,alice@test.com,Alice,true
456,bob@test.com,Bob,false`;

      const result = parseCSV(csv);
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        id: '123',
        email: 'alice@test.com',
        name: 'Alice',
        isstudent: 'true',
      });
    });

    it('correctly parses quoted cells with commas inside quotes', () => {
      const csv = `id,name,skills
789,"Cooper, Alice","Rust, Go, C++"
321,"Doe, John",TypeScript`;

      const result = parseCSV(csv);
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual({
        id: '789',
        name: 'Cooper, Alice',
        skills: 'Rust, Go, C++',
      });
      expect(result[1]).toEqual({
        id: '321',
        name: 'Doe, John',
        skills: 'TypeScript',
      });
    });

    it('handles escaped double quotes within quoted cells', () => {
      const csv = `id,quote
1,"He said ""Hello, world!"""`;

      const result = parseCSV(csv);
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual({
        id: '1',
        quote: 'He said "Hello, world!"',
      });
    });
  });

  describe('loadCSVConnector', () => {
    it('reads file, parses, coercing types and matching by email case-insensitively', async () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(`id,email,name,gpa,isActive
stu_01,ALICE@test.com,Alice,3.92,true
stu_02,bob@test.com,Bob,3.1,false`);

      const connector = loadCSVConnector(
        {
          path: './test.csv',
          identifierColumn: 'email',
        },
        pseudonymSecret
      );

      const result = await connector.lookup('alice@test.com');

      expect(fs.existsSync).toHaveBeenCalled();
      expect(fs.readFileSync).toHaveBeenCalledWith(expect.any(String), 'utf8');

      expect(result).not.toBeNull();
      expect(result?.['email']).toBe('ALICE@test.com');
      expect(result?.['name']).toBe('Alice');
      expect(result?.['gpa']).toBe(3.92); // numeric coercion
      expect(result?.['isactive']).toBe(true); // boolean coercion
      expect(result?.['id']).toBe('stu_01');
      expect(result?.['defaultPassword']).toBeDefined();
      expect(result?.['_source']).toBe('csv');
    });

    it('returns null if CSV file does not exist', async () => {
      vi.mocked(fs.existsSync).mockReturnValue(false);

      const connector = loadCSVConnector(
        {
          path: './missing.csv',
          identifierColumn: 'email',
        },
        pseudonymSecret
      );

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      const result = await connector.lookup('test@test.com');

      expect(result).toBeNull();
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    it('returns null if the identifier does not match any record', async () => {
      vi.mocked(fs.existsSync).mockReturnValue(true);
      vi.mocked(fs.readFileSync).mockReturnValue(`id,email,name
stu_01,alice@test.com,Alice`);

      const connector = loadCSVConnector(
        {
          path: './test.csv',
          identifierColumn: 'email',
        },
        pseudonymSecret
      );

      const result = await connector.lookup('missing@test.com');
      expect(result).toBeNull();
    });
  });
});
