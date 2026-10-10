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
 *
 * root may itself already be a filesystem root ("/" on POSIX, "C:\\" on
 * Windows) if the process happens to start with its cwd there -- it
 * already ends with path.sep in that case, so appending another would
 * produce "//" and reject every real descendant. Only append the
 * separator when root doesn't already end with one.
 */
export function isPathWithinRoot(candidate: string, root: string): boolean {
  if (candidate === root) return true;
  const prefix = root.endsWith(path.sep) ? root : root + path.sep;
  return candidate.startsWith(prefix);
}
