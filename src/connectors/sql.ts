/** Only unquoted SQL identifiers are accepted; values always use parameters. */
export function sqlIdentifier(value: string, quote: '"' | '`', qualified = false): string {
  const parts = value.split('.');
  if ((!qualified && parts.length !== 1) || parts.length > 2 || parts.some(part => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(part))) throw new Error('Invalid SQL identifier');
  return parts.map(part => quote + part + quote).join('.');
}

export function pageBounds(options: { limit?: number; offset?: number } = {}): { limit: number; offset: number } {
  const { limit = 1000, offset = 0 } = options;
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000 || !Number.isInteger(offset) || offset < 0) throw new Error('limit must be 1–1000 and offset must be a nonnegative integer');
  return { limit, offset };
}
