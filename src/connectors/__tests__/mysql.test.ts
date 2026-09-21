import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadMySQLConnector } from '../mysql.js';
const { execute, end, poolOptions } = vi.hoisted(() => ({ execute: vi.fn(), end: vi.fn(), poolOptions: vi.fn() }));
vi.mock('mysql2/promise', () => ({ createPool: (options: unknown) => { poolOptions(options); return { execute, end }; } }));
const config = { connectionString: 'mysql://localhost/test', table: 'users', identifierColumn: 'email' };
describe('MySQL source', () => {
  beforeEach(() => vi.clearAllMocks());
  it('quotes identifiers and binds lookup values', async () => {
    execute.mockResolvedValue([[{ id: '001', email: 'a@test.com' }], []]);
    const connector = loadMySQLConnector(config, 'secret');
    expect((await connector.lookup("a' OR 1=1--"))?.id).toBe('001');
    expect(execute).toHaveBeenCalledWith('SELECT * FROM `users` WHERE `email` = ? LIMIT 1', ["a' OR 1=1--"]);
  });
  it('rejects unsafe identifiers', () => {
    expect(() => loadMySQLConnector({ ...config, table: 'users; DROP TABLE users' }, 'secret')).toThrow('Invalid SQL identifier');
    expect(() => loadMySQLConnector({ ...config, identifierColumn: 'email OR true' }, 'secret')).toThrow();
    expect(execute).not.toHaveBeenCalled();
  });
  it('distinguishes missing holders from connection errors', async () => {
    const connector = loadMySQLConnector(config, 'secret');
    execute.mockResolvedValueOnce([[], []]);
    expect(await connector.lookup('missing')).toBeNull();
    execute.mockRejectedValueOnce(new Error('offline'));
    await expect(connector.lookup('missing')).rejects.toThrow('offline');
  });
  it('probes schema, lists a page, and releases its pool', async () => {
    const connector = loadMySQLConnector(config, 'secret');
    execute.mockResolvedValueOnce([[{ Field: 'email' }], []]);
    await connector.healthCheck!();
    execute.mockResolvedValueOnce([[{ id: '002' }], []]);
    expect(await connector.list!({ limit: 10, offset: 20 })).toEqual([expect.objectContaining({ id: '002' })]);
    expect(execute).toHaveBeenCalledWith('SELECT * FROM `users` ORDER BY `email` LIMIT ? OFFSET ?', [10, 20]);
    await connector.close!();
    expect(end).toHaveBeenCalledOnce();
    execute.mockRejectedValueOnce(new Error('schema offline'));
    await expect(connector.getSchema()).rejects.toThrow('schema offline');
  });

  it('preserves SQL DATE strings and roundtrips listed records through the configured identifier', async () => {
    execute.mockResolvedValue([[{ id: '0001', email: 'holder@example.org', dateOfBirth: '2000-02-29' }], []]);
    const source = loadMySQLConnector(config, 'secret');
    const [holder] = await source.list!();
    expect(poolOptions.mock.calls[0][0].dateStrings).toEqual(['DATE']);
    expect(holder).toMatchObject({ id: '0001', _lookupIdentifier: 'holder@example.org', dateOfBirth: '2000-02-29' });
    expect(await source.lookup(holder._lookupIdentifier!)).toMatchObject({ id: '0001' });
    expect(execute).toHaveBeenLastCalledWith('SELECT * FROM `users` WHERE `email` = ? LIMIT 1', ['holder@example.org']);
  });
});
