import path from 'node:path';
import { describe, it, expect } from 'vitest';
import { isPathWithinRoot } from '../path-containment.js';

describe('isPathWithinRoot', () => {
  const filesystemRoot = path.parse(process.cwd()).root;
  const app = path.join(filesystemRoot, 'app');
  const dist = path.join(app, 'stitch-out', 'dist');

  it('accepts the root itself', () => {
    expect(isPathWithinRoot(app, app)).toBe(true);
  });

  it('accepts a real descendant', () => {
    expect(isPathWithinRoot(dist, app)).toBe(true);
  });

  it('rejects a sibling directory that merely shares the root as a string prefix', () => {
    // The exact false-accept a plain startsWith(root) check lets through.
    const sibling = path.join(filesystemRoot, 'app-evil');
    expect(isPathWithinRoot(sibling, app)).toBe(false);
    expect(isPathWithinRoot(path.join(sibling, 'dist'), app)).toBe(false);
  });

  it('rejects an unrelated absolute path', () => {
    expect(isPathWithinRoot(path.join(filesystemRoot, 'etc', 'passwd'), app)).toBe(false);
  });

  it('rejects a traversal that resolves outside the root', () => {
    expect(isPathWithinRoot(path.resolve(app, '..', 'etc'), app)).toBe(false);
  });

  it('accepts real descendants when root is the filesystem root itself', () => {
    // A filesystem root already ends with the native separator.
    expect(isPathWithinRoot(filesystemRoot, filesystemRoot)).toBe(true);
    expect(isPathWithinRoot(dist, filesystemRoot)).toBe(true);
  });
});
