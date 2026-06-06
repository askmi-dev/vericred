import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadMySQLConnector } from '../mysql.js';

const mockExecute = vi.fn();

vi.mock('mysql2/promise', () => {
  return {
    createPool: () => ({
      execute: mockExecute,
    }),
  };
});

describe('MySQL Connector', () => {
  const pseudonymSecret = 'test_pseudonym_secret_32_bytes_long_!!!';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('correctly retrieves and maps a holder record from MySQL pool', async () => {
    mockExecute.mockResolvedValueOnce([
      [
        {
          id: 'holder_45',
          email: 'alice@example.com',
          name: 'Alice Cooper',
          age: 32,
        }
      ],
      null // second value in tuple is schema fields
    ]);

    const connector = loadMySQLConnector(
      {
        connectionString: 'mysql://localhost:3306/mydb',
        table: 'users',
        identifierColumn: 'email',
      },
      pseudonymSecret
    );

    const result = await connector.lookup('alice@example.com');

    expect(mockExecute).toHaveBeenCalledWith(
      'SELECT * FROM users WHERE email = ? LIMIT 1',
      ['alice@example.com']
    );

    expect(result).not.toBeNull();
    expect(result?.['email']).toBe('alice@example.com');
    expect(result?.['name']).toBe('Alice Cooper');
    expect(result?.['id']).toBe('holder_45');
    expect(result?.['defaultPassword']).toBeDefined();
    expect(result?.['_source']).toBe('mysql');
  });

  it('returns null if the execution returns zero rows', async () => {
    mockExecute.mockResolvedValueOnce([[], null]);

    const connector = loadMySQLConnector(
      {
        connectionString: 'mysql://localhost:3306/mydb',
        table: 'users',
        identifierColumn: 'email',
      },
      pseudonymSecret
    );

    const result = await connector.lookup('not_found@example.com');
    expect(result).toBeNull();
  });

  it('logs error and returns null on execution failure', async () => {
    mockExecute.mockRejectedValueOnce(new Error('Connection lost'));

    const connector = loadMySQLConnector(
      {
        connectionString: 'mysql://localhost:3306/mydb',
        table: 'users',
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
