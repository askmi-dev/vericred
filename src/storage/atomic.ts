import { mkdirSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, rmSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

/** Atomic single-writer replacement, including directory durability on Linux. */
export function atomicWrite(path: string, data: string): void {
  const parent = dirname(path);
  mkdirSync(parent, { recursive: true });
  const temporary = path + '.' + randomUUID() + '.tmp';
  try {
    const fd = openSync(temporary, 'wx', 0o600);
    try { writeFileSync(fd, data, 'utf8'); fsyncSync(fd); }
    finally { closeSync(fd); }
    renameSync(temporary, path);
    if (process.platform !== 'win32') {
      const directory = openSync(parent, 'r');
      try { fsyncSync(directory); } finally { closeSync(directory); }
    }
  } finally { rmSync(temporary, { force: true }); }
}
