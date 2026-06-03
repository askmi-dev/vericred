/**
 * SD-JWT Disclosure Serialization Tests
 *
 * Verifies:
 *   - Disclosure encodes to [salt, name, value]
 *   - Digest is SHA-256 of encoded disclosure
 *   - Raw claim values do NOT appear in the JWT payload (_sd approach)
 *   - Combined format uses ~ separator
 *   - Partial disclosure: one claim can be revealed without revealing others
 */

import { describe, it, expect } from 'vitest';
import { createHash } from 'crypto';
import {
  createDisclosure,
  buildSdJwtPayload,
  combineSdJwt,
  decodeDisclosure,
  verifyDisclosureDigest,
} from '../disclosures.js';

describe('createDisclosure', () => {
  it('returns encoded and digest', () => {
    const { encoded, digest } = createDisclosure('age_over_18', true);
    expect(typeof encoded).toBe('string');
    expect(typeof digest).toBe('string');
    expect(encoded.length).toBeGreaterThan(10);
    expect(digest.length).toBeGreaterThan(10);
  });

  it('encoded decodes to [salt, name, value]', () => {
    const { encoded } = createDisclosure('age_over_18', true);
    const [salt, name, value] = decodeDisclosure(encoded);
    expect(typeof salt).toBe('string');
    expect(name).toBe('age_over_18');
    expect(value).toBe(true);
  });

  it('digest is base64url(SHA-256(encoded))', () => {
    const { encoded, digest } = createDisclosure('organization', 'askmi GmbH');
    const expected = createHash('sha256').update(encoded).digest('base64url');
    expect(digest).toBe(expected);
  });

  it('produces different salt on each call (non-deterministic)', () => {
    const a = createDisclosure('foo', 'bar');
    const b = createDisclosure('foo', 'bar');
    expect(a.encoded).not.toBe(b.encoded);
    expect(a.digest).not.toBe(b.digest);
  });

  it('handles boolean, number, string, null values', () => {
    for (const value of [true, false, 42, 'hello', null]) {
      const { encoded } = createDisclosure('x', value);
      const [, , decoded] = decodeDisclosure(encoded);
      expect(decoded).toBe(value);
    }
  });
});

describe('buildSdJwtPayload', () => {
  const claims = { age_over_18: true, age_over_21: false, age_attested_at: '2026-06-03' };

  it('produces one hash and one disclosure per claim', () => {
    const { sdHashes, disclosures } = buildSdJwtPayload(claims);
    expect(sdHashes).toHaveLength(3);
    expect(disclosures).toHaveLength(3);
  });

  it('raw claim values do NOT appear in sdHashes or payload (only digests)', () => {
    const { sdHashes } = buildSdJwtPayload(claims);
    // Digests should not be the claim values themselves
    for (const hash of sdHashes) {
      expect(hash).not.toBe('true');
      expect(hash).not.toBe('false');
      expect(hash).not.toBe('2026-06-03');
    }
  });

  it('each disclosure decodes to a [salt, name, value] triple', () => {
    const { disclosures } = buildSdJwtPayload(claims);
    const names = disclosures.map(d => decodeDisclosure(d)[1]);
    expect(names).toContain('age_over_18');
    expect(names).toContain('age_over_21');
    expect(names).toContain('age_attested_at');
  });

  it('each digest matches its disclosure', () => {
    const { sdHashes, disclosures } = buildSdJwtPayload(claims);
    for (let i = 0; i < sdHashes.length; i++) {
      expect(verifyDisclosureDigest(disclosures[i]!, sdHashes[i]!)).toBe(true);
    }
  });
});

describe('combineSdJwt', () => {
  it('appends disclosures with ~ separator', () => {
    const combined = combineSdJwt('FAKEJWT', ['d1', 'd2', 'd3']);
    expect(combined).toBe('FAKEJWT~d1~d2~d3~');
  });

  it('includes trailing ~ even with no disclosures', () => {
    const combined = combineSdJwt('FAKEJWT', []);
    expect(combined).toBe('FAKEJWT~');
  });

  it('combined format starts with the JWT', () => {
    const combined = combineSdJwt('FAKEJWT', ['d1']);
    expect(combined.split('~')[0]).toBe('FAKEJWT');
  });
});

describe('decodeDisclosure', () => {
  it('throws on malformed base64url', () => {
    expect(() => decodeDisclosure('not-valid-json-base64')).toThrow();
  });

  it('throws when array length is not 3', () => {
    const bad = Buffer.from(JSON.stringify(['salt', 'name'])).toString('base64url');
    expect(() => decodeDisclosure(bad)).toThrow('expected [salt, name, value]');
  });
});

describe('verifyDisclosureDigest', () => {
  it('returns true for matching digest', () => {
    const { encoded, digest } = createDisclosure('role', 'Engineer');
    expect(verifyDisclosureDigest(encoded, digest)).toBe(true);
  });

  it('returns false for wrong digest', () => {
    const { encoded } = createDisclosure('role', 'Engineer');
    expect(verifyDisclosureDigest(encoded, 'wrongdigest')).toBe(false);
  });
});

describe('Partial disclosure — AgeCredential scenario', () => {
  it('holder can reveal age_over_18 without revealing age_over_21', () => {
    // Simulates the holder selecting which disclosures to present
    const allClaims = { age_over_18: true, age_over_21: false, age_attested_at: '2026-06-03' };
    const { sdHashes, disclosures } = buildSdJwtPayload(allClaims);

    // Find the age_over_18 disclosure
    const d18 = disclosures.find(d => decodeDisclosure(d)[1] === 'age_over_18')!;
    const d21 = disclosures.find(d => decodeDisclosure(d)[1] === 'age_over_21')!;

    // Holder presents only age_over_18
    const presented = [d18];
    const combined = combineSdJwt('FAKEJWT', presented);

    // Verifier: age_over_18 is verifiable, age_over_21 is not present
    const parts = combined.split('~').filter(Boolean).slice(1);
    expect(parts).toHaveLength(1);

    const [, revealedName, revealedValue] = decodeDisclosure(parts[0]!);
    expect(revealedName).toBe('age_over_18');
    expect(revealedValue).toBe(true);

    // age_over_21 disclosure is not in the presented set
    expect(parts).not.toContain(d21);

    // But its hash is still in sdHashes (verifier sees the commitment exists)
    const hash21 = createHash('sha256').update(d21).digest('base64url');
    expect(sdHashes).toContain(hash21);
  });
});
