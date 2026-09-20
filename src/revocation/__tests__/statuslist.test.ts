import { describe, it, expect, beforeEach } from 'vitest';
import { readFileSync, writeFileSync, existsSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { jwtVerify } from 'jose';
import { assignStatusIndex, revokeCredential, buildStatusListJWT, getListId, getIssuedCredentials, hasList, LIST_SIZE } from '../statuslist.js';
import { getIssuerKeyPair } from '../../keys/manager.js';

describe('StatusList2021 persistence, interoperable encoding and rollover', () => {
  const storePath = () => join(process.env.DATA_DIR!, 'statuslist.json');
  beforeEach(() => {
    if (existsSync(storePath())) unlinkSync(storePath());
  });
  async function decodedList(listId?: string) {
    const jwt = await buildStatusListJWT(listId);
    const { publicKey } = await getIssuerKeyPair();
    const { payload } = await jwtVerify(jwt, publicKey, { algorithms: ['ES256'] });
    expect(payload.type).toContain('StatusList2021Credential');
    const subject = payload.credentialSubject as { type: string; statusPurpose: string; encodedList: string };
    expect(subject.type).toBe('StatusList2021');
    expect(subject.statusPurpose).toBe('revocation');
    const compressed = Buffer.from(subject.encodedList, 'base64url');
    // An independent consumer must be able to GZIP-decompress the advertised StatusList2021 encoding.
    expect([...compressed.subarray(0, 2)]).toEqual([0x1f, 0x8b]);
    const bytes = gunzipSync(compressed);
    expect(bytes.length * 8).toBeGreaterThanOrEqual(131072);
    return bytes;
  }
  it('assigns sequential indices and persists credentials with their list identity', () => {
    const first = assignStatusIndex('vc1', 'a@example.com');
    const second = assignStatusIndex('vc2', 'b@example.com');
    expect(first.statusIndex).toBe(0);
    expect(second.statusIndex).toBe(1);
    expect(first.listId).toBe(second.listId);
    expect(first.listId).toBe(getListId());
    expect(getIssuedCredentials().map(c => [c.credentialId, c.listId])).toEqual([['vc1', first.listId], ['vc2', first.listId]]);
  });
  it('revokes once and encodes the revoked index in a signed GZIP-compressed list', async () => {
    const first = assignStatusIndex('vc1', 'a@example.com');
    assignStatusIndex('vc2', 'b@example.com');
    expect(revokeCredential('vc2')).toBe(true);
    expect(revokeCredential('vc2')).toBe(false);
    expect(revokeCredential('missing')).toBe(false);
    expect(getIssuedCredentials()[1]).toMatchObject({ revoked: true, revokedAt: expect.any(String) });
    const bytes = await decodedList(first.listId);
    expect(bytes[0]).toBe(64); // Index 1 is the second most significant bit (StatusList2021 section 2.2).
    expect(bytes.subarray(1).every(byte => byte === 0)).toBe(true);
  });
  it('rolls over at capacity while preserving old list URLs and revocations', async () => {
    const old = assignStatusIndex('old-first', 'holder@example.com');
    const persisted = JSON.parse(readFileSync(storePath(), 'utf8'));
    // Seed the boundary to test the actual allocation path without 131,072 filesystem writes.
    persisted.nextIndex = LIST_SIZE - 1;
    writeFileSync(storePath(), JSON.stringify(persisted));
    const last = assignStatusIndex('old-last', 'holder@example.com');
    const next = assignStatusIndex('new-first', 'holder@example.com');
    expect(last).toEqual({ listId: old.listId, statusIndex: LIST_SIZE - 1 });
    expect(next.statusIndex).toBe(0);
    expect(next.listId).not.toBe(old.listId);
    expect(getListId()).toBe(next.listId);
    expect(hasList(old.listId)).toBe(true);
    expect(hasList(next.listId)).toBe(true);
    revokeCredential('old-last');
    revokeCredential('new-first');
    const oldBytes = await decodedList(old.listId);
    const newBytes = await decodedList(next.listId);
    expect(oldBytes[0]).toBe(0);
    expect(oldBytes[oldBytes.length - 1]).toBe(1);
    expect(newBytes[0]).toBe(128);
    expect(newBytes[newBytes.length - 1]).toBe(0);
    expect(getIssuedCredentials().find(c => c.credentialId === 'old-last')?.listId).toBe(old.listId);
  });
  it('fails closed for unknown lists', async () => {
    getListId();
    await expect(buildStatusListJWT('not-a-list')).rejects.toThrow('Unknown status list');
  });
});
