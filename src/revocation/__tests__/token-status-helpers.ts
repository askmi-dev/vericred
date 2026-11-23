/**
 * Test helpers: read an IETF Token Status List the way an independent
 * verifier would (draft-ietf-oauth-status-list). Not part of the gateway --
 * VeriCred only publishes lists; checking them is the verifier's job.
 */
import { inflateSync } from 'zlib';

/** Decompress a status_list.lst value (base64url of ZLIB/DEFLATE bytes). */
export function decodeStatusList(lst: string): Uint8Array {
  return new Uint8Array(inflateSync(Buffer.from(lst, 'base64url')));
}

/** Status value at idx for a 1-bit list: 0 = VALID, 1 = INVALID. */
export function statusAt(lst: string, idx: number): number {
  const bytes = decodeStatusList(lst);
  return (bytes[Math.floor(idx / 8)]! >> (idx % 8)) & 1;
}
