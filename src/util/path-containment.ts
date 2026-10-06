import path from 'path';

/**
 * True if `candidate` (an already-resolved absolute path) is `root`
 * itself or a real descendant of it -- lexical containment on normalized
 * paths, not a symlink sandbox (callers needing protection against
 * symlink escapes should resolve with fs.realpathSync first).
 *
 * A plain `candidate.startsWith(root)` -- CodeQL's own documented
 * path-injection fix -- has a classic false-accept: if root is "/app",
 * the sibling directory "/app-evil" also starts with that string.
 * Requiring the path separator (or exact equality) after the prefix
 * closes that gap.
 */
export function isPathWithinRoot(candidate: string, root: string): boolean {
  return candidate === root || candidate.startsWith(root + path.sep);
}
