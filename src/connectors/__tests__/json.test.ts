import { describe, it, expect } from 'vitest';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadJsonConnector } from '../json.js';
describe('JSON holder lookup identifiers', () => {
  it('preserves numeric stable ids and returns an identifier the connector accepts', async () => {
    const path = join(process.env.DATA_DIR!, 'numeric-holders.json');
    writeFileSync(path, JSON.stringify([{ id: 42, email: 'holder@example.org' }]));
    const source = loadJsonConnector(path);
    const [holder] = await source.list!();
    expect(holder.id).toBe(42);
    expect(holder._lookupIdentifier).toBe('42');
    expect(await source.lookup(holder._lookupIdentifier!)).toMatchObject({ id: 42 });
  });
  it('uses email when a record has no id and ignores an injected transport identifier', async () => {
    const path = join(process.env.DATA_DIR!, 'email-holders.json');
    writeFileSync(path, JSON.stringify([{ email: 'holder@example.org', _lookupIdentifier: 'unrelated-holder' }]));
    const source = loadJsonConnector(path);
    const [holder] = await source.list!();
    expect(holder._lookupIdentifier).toBe('holder@example.org');
    expect(await source.lookup(holder._lookupIdentifier!)).toMatchObject({ email: 'holder@example.org' });
  });
});
