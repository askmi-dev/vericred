import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, rmSync, mkdirSync, writeFileSync } from 'fs';
import { assignStatusIndex, revokeCredential, buildStatusListJWT, getListId, getIssuedCredentials, getStatusListResponse } from '../statuslist.js';
import { jwtVerify, decodeProtectedHeader } from 'jose';
import { getIssuerKeyPair } from '../../keys/manager.js';
import { statusAt } from './token-status-helpers.js';

describe('Token Status List Manager', () => {
  const DATA_DIR = './data-test-revocation';

  beforeEach(() => {
    process.env['DATA_DIR'] = DATA_DIR;
    if (existsSync(DATA_DIR)) rmSync(DATA_DIR, { recursive: true, force: true });
    mkdirSync(DATA_DIR, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(DATA_DIR)) rmSync(DATA_DIR, { recursive: true, force: true });
  });

  it('assigns distinct random indices and persists them', () => {
    const { statusIndex: idx1, listId: lid1 } = assignStatusIndex('vc1', 'a@example.com');
    const { statusIndex: idx2, listId: lid2 } = assignStatusIndex('vc2', 'b@example.com');

    expect(idx1).not.toBe(idx2);
    // Not issuance order: 50 sequential-looking draws would be ~impossible at random
    const more = Array.from({ length: 50 }, (_, i) => assignStatusIndex(`m${i}`, 'm@example.com').statusIndex);
    expect(more.some((v, i) => i > 0 && v !== more[i - 1]! + 1)).toBe(true);
    expect(new Set(more).size).toBe(50);
    expect(lid1).toBe(lid2);
    expect(lid1).toBe(getListId());

    const creds = getIssuedCredentials();
    expect(creds).toHaveLength(52);
    expect(creds[0].credentialId).toBe('vc1');
    expect(creds[1].credentialId).toBe('vc2');
  });

  it('revokes a credential and flips the bit in statuslist store', () => {
    assignStatusIndex('vc1', 'a@example.com');
    const ok = revokeCredential('vc1');
    expect(ok).toBe(true);

    const creds = getIssuedCredentials();
    expect(creds[0].revoked).toBe(true);
    expect(creds[0].revokedAt).toBeDefined();

    // Revoking again should return false
    const ok2 = revokeCredential('vc1');
    expect(ok2).toBe(false);
  });

  it('revokes every copy of a batch together, and only that batch', () => {
    assignStatusIndex('b1', 'a@example.com', 'batch-A');
    assignStatusIndex('b2', 'a@example.com', 'batch-A');
    assignStatusIndex('other', 'b@example.com', 'batch-B');

    expect(revokeCredential('b2')).toBe(true);
    const byId = Object.fromEntries(getIssuedCredentials().map(c => [c.credentialId, c.revoked]));
    expect(byId).toEqual({ b1: true, b2: true, other: false });
  });

  it('keeps serving a migrated legacy list as StatusList2021 so revocations never fail open', async () => {
    // Store written by the pre-Token-Status-List version: sequential indices,
    // no format marker, index 1 already revoked.
    const legacyListId = 'legacy-list-0001';
    writeFileSync(`${DATA_DIR}/statuslist.json`, JSON.stringify({
      listId: legacyListId,
      nextIndex: 3,
      revokedIndices: [1],
      issuedCredentials: [
        { credentialId: 'old0', holderEmail: 'a@example.com', statusIndex: 0, issuedAt: '2026-11-01T00:00:00Z', revoked: false },
        { credentialId: 'old1', holderEmail: 'b@example.com', statusIndex: 1, issuedAt: '2026-11-01T00:00:00Z', revoked: true, revokedAt: '2026-11-02T00:00:00Z' },
        { credentialId: 'old2', holderEmail: 'c@example.com', statusIndex: 2, issuedAt: '2026-11-01T00:00:00Z', revoked: false },
      ],
    }));

    // New credentials go to a fresh Token Status List ID, not the legacy URL.
    const { listId: newListId, statusIndex: newIdx } = assignStatusIndex('new0', 'd@example.com');
    expect(newListId).not.toBe(legacyListId);
    expect(getListId()).toBe(newListId);

    // A revocation of a legacy credential after migration still reaches the legacy list.
    expect(revokeCredential('old2')).toBe(true);

    const { publicKey } = await getIssuerKeyPair();
    const legacy = await getStatusListResponse(legacyListId);
    expect(legacy?.contentType).toBe('application/jwt');
    const { payload: legacyPayload } = await jwtVerify(legacy!.body, publicKey);
    expect(legacyPayload.type).toContain('StatusList2021Credential');
    const bits = Buffer.from((legacyPayload.credentialSubject as any).encodedList, 'base64url');
    expect(bits[0]).toBe(0b110); // old1 (bit 1) and old2 (bit 2) revoked, old0 active

    const current = await getStatusListResponse(newListId);
    expect(current?.contentType).toBe('application/statuslist+jwt');
    const { payload } = await jwtVerify(current!.body, publicKey);
    const lst = (payload.status_list as { lst: string }).lst;
    expect(statusAt(lst, newIdx)).toBe(0);
    // Legacy revocations must not leak into the new list's bits.
    expect([1, 2].filter(i => i !== newIdx).every(i => statusAt(lst, i) === 0)).toBe(true);

    expect(await getStatusListResponse('unknown-list')).toBeNull();
  });

  it('builds a signed IETF Token Status List', async () => {
    const { statusIndex: active } = assignStatusIndex('vc1', 'a@example.com');
    const { statusIndex: revoked } = assignStatusIndex('vc2', 'b@example.com');
    revokeCredential('vc2');

    const jwt = await buildStatusListJWT();
    expect(decodeProtectedHeader(jwt).typ).toBe('statuslist+jwt');
    const { publicKey } = await getIssuerKeyPair();
    const { payload } = await jwtVerify(jwt, publicKey);

    expect((payload.sub as string).endsWith(`/status/${getListId()}`)).toBe(true);
    expect(typeof payload.exp).toBe('number');
    const list = payload.status_list as { bits: number; lst: string };
    expect(list.bits).toBe(1);
    expect(statusAt(list.lst, active)).toBe(0);
    expect(statusAt(list.lst, revoked)).toBe(1);
  });

});
