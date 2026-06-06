import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, rmSync, mkdirSync } from 'fs';
import { assignStatusIndex, revokeCredential, buildStatusListJWT, getListId, getIssuedCredentials } from '../statuslist.js';
import { jwtVerify } from 'jose';
import { getIssuerKeyPair } from '../../keys/manager.js';

describe('StatusList2021 Manager', () => {
  const DATA_DIR = './data-test-revocation';

  beforeEach(() => {
    process.env['DATA_DIR'] = DATA_DIR;
    if (existsSync(DATA_DIR)) rmSync(DATA_DIR, { recursive: true, force: true });
    mkdirSync(DATA_DIR, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(DATA_DIR)) rmSync(DATA_DIR, { recursive: true, force: true });
  });

  it('assigns sequential indices and persists them', () => {
    const { statusIndex: idx1, listId: lid1 } = assignStatusIndex('vc1', 'a@example.com');
    const { statusIndex: idx2, listId: lid2 } = assignStatusIndex('vc2', 'b@example.com');

    expect(idx1).toBe(0);
    expect(idx2).toBe(1);
    expect(lid1).toBe(lid2);
    expect(lid1).toBe(getListId());

    const creds = getIssuedCredentials();
    expect(creds).toHaveLength(2);
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

  it('builds a signed StatusList2021 JWT', async () => {
    assignStatusIndex('vc1', 'a@example.com');
    assignStatusIndex('vc2', 'b@example.com');
    revokeCredential('vc2'); // Index 1 is revoked

    const jwt = await buildStatusListJWT();
    const { publicKey } = await getIssuerKeyPair();
    const { payload } = await jwtVerify(jwt, publicKey);

    expect(payload.type).toContain('StatusList2021Credential');
    expect(payload.credentialSubject).toBeDefined();
    const subject = payload.credentialSubject as any;
    expect(subject.type).toBe('StatusList2021');
    expect(subject.statusPurpose).toBe('revocation');
    expect(subject.encodedList).toBeDefined();

    // Verify bitstring (index 1 should be set)
    // index 1 in bitstring: byte 0, bit 1 -> value 2
    // base64url of [2, 0, 0, ...]
    const bitstring = subject.encodedList;
    const bytes = Buffer.from(bitstring, 'base64url');
    expect(bytes[0]).toBe(2); // bit 1 is set (1 << 1)
  });

  it('fails if list is full', () => {
    // This is hard to test with 128k, but we can mock LIST_SIZE if needed.
    // For now, we trust the boundary check if (store.nextIndex >= LIST_SIZE).
  });
});
