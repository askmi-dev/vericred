import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadPostgresConnector } from '../postgres.js';

const mockQuery = vi.fn();

vi.mock('pg', () => {
  return {
    default: {
      Pool: class {
        query = mockQuery;
      }
    }
  };
});

describe('PostgreSQL Connector', () => {
  const pseudonymSecret = 'test_pseudonym_secret_32_bytes_long_!!!';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('correctly retrieves and maps a holder record from PostgreSQL pool', async () => {
    mockQuery.mockResolvedValueOnce({
      rows: [
        {
          id: 'holder_99',
          email: 'bob@example.com',
          name: 'Bob Jenkins',
          age: 28,
        }
      ]
    });

    const connector = loadPostgresConnector(
      {
        connectionString: 'postgresql://localhost:5432/mydb',
        table: 'students_records',
        identifierColumn: 'email',
      },
      pseudonymSecret
    );

    const result = await connector.lookup('bob@example.com');

    expect(mockQuery).toHaveBeenCalledWith(
      'SELECT * FROM students_records WHERE email = $1 LIMIT 1',
      ['bob@example.com']
    );

    expect(result).not.toBeNull();
    expect(result?.['email']).toBe('bob@example.com');
    expect(result?.['name']).toBe('Bob Jenkins');
    expect(result?.['id']).toBe('holder_99');
    expect(result?.['defaultPassword']).toBeDefined();
    expect(result?.['_source']).toBe('postgres');
  });

  it('returns null if the query yields no rows', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });

    const connector = loadPostgresConnector(
      {
        connectionString: 'postgresql://localhost:5432/mydb',
        table: 'students_records',
        identifierColumn: 'email',
      },
      pseudonymSecret
    );

    const result = await connector.lookup('not_found@example.com');
    expect(result).toBeNull();
  });

  it('logs error and returns null on query exception', async () => {
    mockQuery.mockRejectedValueOnce(new Error('Connection timeout'));

    const connector = loadPostgresConnector(
      {
        connectionString: 'postgresql://localhost:5432/mydb',
        table: 'students_records',
        identifierColumn: 'email',
      },
      pseudonymSecret
    );

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const result = await connector.lookup('error@example.com');
    
    expect(result).toBeNull();
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});
