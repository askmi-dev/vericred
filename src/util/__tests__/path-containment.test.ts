import { describe, it, expect } from 'vitest';
import { isPathWithinRoot } from '../path-containment.js';

describe('isPathWithinRoot', () => {
  it('accepts the root itself', () => {
    expect(isPathWithinRoot('/app', '/app')).toBe(true);
  });

  it('accepts a real descendant', () => {
    expect(isPathWithinRoot('/app/stitch-out/dist', '/app')).toBe(true);
  });

  it('rejects a sibling directory that merely shares the root as a string prefix', () => {
    // The exact false-accept a plain startsWith(root) check lets through.
    expect(isPathWithinRoot('/app-evil', '/app')).toBe(false);
    expect(isPathWithinRoot('/app-evil/dist', '/app')).toBe(false);
  });

  it('rejects an unrelated absolute path', () => {
    expect(isPathWithinRoot('/etc/passwd', '/app')).toBe(false);
  });

  it('rejects a path that only resolves inside root lexically after traversal, on the unresolved candidate', () => {
    // isPathWithinRoot assumes the caller already resolved `..` segments
    // (path.resolve does this); fed a resolved, outside-root candidate
    // ("/app/../etc"  -> "/etc"), it must still reject it.
    expect(isPathWithinRoot('/etc', '/app')).toBe(false);
  });

  it('accepts real descendants when root is the filesystem root itself', () => {
    // root ("/") already ends with path.sep -- naively appending another
    // separator would produce "//", which no real absolute path starts
    // with, rejecting every descendant. A process that happens to start
    // with its cwd at "/" must still be able to serve files under it.
    expect(isPathWithinRoot('/', '/')).toBe(true);
    expect(isPathWithinRoot('/app/stitch-out/dist', '/')).toBe(true);
  });
});
