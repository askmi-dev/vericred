import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadPostgresConnector } from '../postgres.js';
const { query, end, poolOptions, on } = vi.hoisted(() => ({ query: vi.fn(), end: vi.fn(), poolOptions: vi.fn(), on: vi.fn() }));
vi.mock('pg', async importOriginal => {
  const actual = await importOriginal<typeof import('pg')>();
  return { default: { ...actual.default, Pool: class {
    constructor(options: unknown) { poolOptions(options); }
    query = query; end = end; on = on;
  } } };
});
const config = { connectionString: 'postgresql://localhost/test', table: 'public.students', identifierColumn: 'email' };
describe('Postgres source', () => {
  beforeEach(() => vi.clearAllMocks());
  it('quotes identifiers and binds holder identifiers as values', async () => {
    query.mockResolvedValue({ rows: [{ id: '001', email: 'a@test.com' }] });
    const connector = loadPostgresConnector(config, 'secret');
    expect((await connector.lookup("a' OR 1=1--"))?.id).toBe('001');
    expect(query).toHaveBeenCalledWith('SELECT * FROM "public"."students" WHERE "email" = $1 LIMIT 1', ["a' OR 1=1--"]);
  });
  it('rejects unsafe identifiers before accessing the driver', () => {
    expect(() => loadPostgresConnector({ ...config, table: 'users; DROP TABLE users' }, 'secret')).toThrow('Invalid SQL identifier');
    expect(() => loadPostgresConnector({ ...config, identifierColumn: 'email OR true' }, 'secret')).toThrow();
    expect(query).not.toHaveBeenCalled();
  });
  it('distinguishes missing holders from database failure', async () => {
    const connector = loadPostgresConnector(config, 'secret');
    query.mockResolvedValueOnce({ rows: [] });
    expect(await connector.lookup('missing')).toBeNull();
    query.mockRejectedValueOnce(new Error('database offline'));
    await expect(connector.lookup('missing')).rejects.toThrow('database offline');
  });
  it('probes real schema and closes its pool', async () => {
    const connector = loadPostgresConnector(config, 'secret');
    query.mockResolvedValue({ fields: [{ name: 'id' }, { name: 'email' }] });
    await connector.healthCheck!();
    expect(await connector.getSchema()).toEqual(['id', 'email']);
    await connector.close!();
    expect(end).toHaveBeenCalledOnce();
    query.mockRejectedValueOnce(new Error('schema offline'));
    await expect(connector.getSchema()).rejects.toThrow('schema offline');
  });
  it('paginates source records and rejects invalid pagination', async () => {
    const connector = loadPostgresConnector(config, 'secret');
    query.mockResolvedValue({ rows: [{ id: '002' }] });
    expect(await connector.list!({ limit: 10, offset: 20 })).toEqual([expect.objectContaining({ id: '002', _source: 'postgres' })]);
    expect(query).toHaveBeenCalledWith('SELECT * FROM "public"."students" ORDER BY "email" LIMIT $1 OFFSET $2', [10, 20]);
    await expect(connector.list!({ limit: -1 })).rejects.toThrow();
  });

  it('keeps a date-only SQL value intact and delegates timestamp parsing', async () => {
    query.mockResolvedValue({ rows: [] });
    const source = loadPostgresConnector(config, 'secret');
    await source.lookup('missing');
    const parser = poolOptions.mock.calls[0][0].types.getTypeParser;
    expect(parser(1082)('2000-02-29')).toBe('2000-02-29');
    expect(parser(1082, 'text')('1990-01-01')).toBe('1990-01-01');
    expect(parser(1184, 'text')('2000-02-29 00:00:00+14')).toBeInstanceOf(Date);
    expect(on).toHaveBeenCalledWith('error', expect.any(Function));
  });
  it('roundtrips a listed holder through its configured identifier rather than its stable id', async () => {
    query.mockResolvedValue({ rows: [{ id: '0001', email: 'holder@example.org', dateOfBirth: '2000-02-29' }] });
    const source = loadPostgresConnector(config, 'secret');
    const [holder] = await source.list!();
    expect(holder).toMatchObject({ id: '0001', _lookupIdentifier: 'holder@example.org', dateOfBirth: '2000-02-29' });
    expect(await source.lookup(holder._lookupIdentifier!)).toMatchObject({ id: '0001' });
    expect(query).toHaveBeenLastCalledWith('SELECT * FROM "public"."students" WHERE "email" = $1 LIMIT 1', ['holder@example.org']);
  });
});
