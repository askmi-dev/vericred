import { describe, it, expect } from 'vitest';
import { writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { loadManualConnector, ManualRegistry } from '../manual.js';
describe('Manual registry', () => {
  it('persists changes and isolates different source files', async () => {
    const first = join(process.env.DATA_DIR!, 'manual-first.json');
    const second = join(process.env.DATA_DIR!, 'manual-second.json');
    const registry = new ManualRegistry(first);
    expect(existsSync(first)).toBe(false);
    registry.add({ id: 'one', email: 'one@test.com' });
    expect(new ManualRegistry(first).find('one@test.com')?.id).toBe('one');
    registry.add({ id: 'one', email: 'new@test.com' });
    expect(registry.list()).toHaveLength(1);
    const other = new ManualRegistry(second);
    other.add({ id: 'two', email: 'two@test.com' });
    const source = loadManualConnector({ path: second }, 'secret');
    expect(await source.lookup('one')).toBeNull();
    expect((await source.list!())[0].id).toBe('two');
    registry.remove('one');
    expect(new ManualRegistry(first).list()).toEqual([]);
  });
  it('surfaces malformed data instead of replacing it with empty data', () => {
    const file = join(process.env.DATA_DIR!, 'malformed-manual.json');
    writeFileSync(file, '{"broken":true}');
    expect(() => new ManualRegistry(file)).toThrow('array of objects');
  });
});
