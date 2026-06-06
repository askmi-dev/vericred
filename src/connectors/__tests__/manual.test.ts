import { describe, it, expect, vi, beforeEach } from 'vitest';
import { loadManualConnector, ManualRegistry } from '../manual.js';
import fs from 'fs';

vi.mock('fs', () => {
  return {
    default: {
      existsSync: vi.fn(),
      readFileSync: vi.fn(),
      writeFileSync: vi.fn(),
      mkdirSync: vi.fn(),
    }
  };
});

describe('Manual Entry Connector & Registry', () => {
  const pseudonymSecret = 'test_pseudonym_secret_32_bytes_long_!!!';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('correctly instantiates database and can register, load, find, and update records', () => {
    vi.mocked(fs.existsSync).mockReturnValue(false); // file doesn't exist yet

    const registry = new ManualRegistry('./data/manual_test.json');

    expect(fs.mkdirSync).toHaveBeenCalled();
    expect(fs.writeFileSync).toHaveBeenCalled();

    // Register a new holder
    registry.add({
      id: 'manual_user_1',
      email: 'charlie@example.com',
      name: 'Charlie Smith',
    });

    expect(fs.writeFileSync).toHaveBeenCalled();

    // List records
    const list = registry.list();
    expect(list).toHaveLength(1);
    expect(list[0]['name']).toBe('Charlie Smith');

    // Find record by email
    const matchEmail = registry.find('charlie@example.com');
    expect(matchEmail).not.toBeNull();
    expect(matchEmail?.['name']).toBe('Charlie Smith');

    // Find record by id
    const matchId = registry.find('manual_user_1');
    expect(matchId).not.toBeNull();
    expect(matchId?.['name']).toBe('Charlie Smith');

    // Update existing record
    registry.add({
      id: 'manual_user_1',
      email: 'charlie@example.com',
      name: 'Charlie S. Williams',
    });
    expect(registry.list()).toHaveLength(1);
    expect(registry.find('manual_user_1')?.['name']).toBe('Charlie S. Williams');

    // Delete record
    registry.remove('manual_user_1');
    expect(registry.list()).toHaveLength(0);
    expect(registry.find('manual_user_1')).toBeNull();
  });

  it('correctly loads records from JSON file if file exists', () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(
      JSON.stringify([
        { id: 'uid_1', email: 'dave@example.com', name: 'Dave' }
      ])
    );

    const registry = new ManualRegistry('./data/manual_existing.json');
    expect(fs.readFileSync).toHaveBeenCalled();
    expect(registry.list()).toHaveLength(1);
    expect(registry.find('dave@example.com')?.['name']).toBe('Dave');
  });

  it('integrates loadManualConnector with the registry', async () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(
      JSON.stringify([
        { id: 'uid_2', email: 'eve@example.com', name: 'Eve', age: 24 }
      ])
    );

    const connector = loadManualConnector(
      { path: './data/manual_existing.json' },
      pseudonymSecret
    );

    const result = await connector.lookup('eve@example.com');
    expect(result).not.toBeNull();
    expect(result?.['name']).toBe('Eve');
    expect(result?.['age']).toBe(24);
    expect(result?.['id']).toBe('uid_2');
    expect(result?.['defaultPassword']).toBeDefined();
    expect(result?.['_source']).toBe('manual');
  });
});
