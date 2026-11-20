import { writeSync } from 'node:fs';

export async function load(url, context, nextLoad) {
  const result = await nextLoad(url, context);
  if (/\/oid4vp\/router\.(ts|js)$/.test(url)) {
    writeSync(2, '[test] verifier module loaded\n');
  }
  return result;
}
