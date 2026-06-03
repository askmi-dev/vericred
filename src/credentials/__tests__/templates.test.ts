/**
 * Credential Template Tests
 *
 * Tests:
 *  - AgeCredential: never emits dateOfBirth
 *  - AgeCredential: 17-year-old fails age_over_18
 *  - AgeCredential: birthday boundary (exact day)
 *  - AgeCredential: invalid templateOptions rejected
 *  - EmployeeCredential: never emits email, dateOfBirth, or address
 *  - MembershipCredential: works without name and email
 *  - Registry: unknown type throws descriptive error
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { getTemplate, listTemplates } from '../registry.js';

// Load templates (side-effect registration)
import '../templates/age.js';
import '../templates/employee.js';
import '../templates/membership.js';

// ---- helpers ----

/** Build a YYYY-MM-DD string for someone who is exactly `years` old today (UTC) */
function dobExactAge(years: number): string {
  const now = new Date();
  const d = new Date(Date.UTC(now.getUTCFullYear() - years, now.getUTCMonth(), now.getUTCDate()));
  return d.toISOString().slice(0, 10);
}

/** Build a DOB for someone who turns `years` tomorrow (UTC) — still one day short */
function dobOneDayShort(years: number): string {
  const now = new Date();
  const tomorrow = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  const d = new Date(Date.UTC(tomorrow.getUTCFullYear() - years, tomorrow.getUTCMonth(), tomorrow.getUTCDate()));
  return d.toISOString().slice(0, 10);
}

// ---- AgeCredential ----

describe('AgeCredential', () => {
  const template = getTemplate('AgeCredential');

  it('never emits dateOfBirth in claims', () => {
    const claims = template.buildClaims({ dateOfBirth: dobExactAge(25) });
    expect(Object.keys(claims)).not.toContain('dateOfBirth');
  });

  it('emits age_over_18 = true for a 25-year-old', () => {
    const claims = template.buildClaims({ dateOfBirth: dobExactAge(25) });
    expect(claims['age_over_18']).toBe(true);
  });

  it('emits age_over_18 = false for a 17-year-old', () => {
    const dob = dobExactAge(17);
    const claims = template.buildClaims({ dateOfBirth: dob });
    expect(claims['age_over_18']).toBe(false);
  });

  it('birthday boundary: person is exactly 18 today → age_over_18 = true', () => {
    const claims = template.buildClaims({ dateOfBirth: dobExactAge(18) });
    expect(claims['age_over_18']).toBe(true);
  });

  it('birthday boundary: person turns 18 tomorrow → age_over_18 = false', () => {
    const dob = dobOneDayShort(18);
    const claims = template.buildClaims({ dateOfBirth: dob });
    expect(claims['age_over_18']).toBe(false);
  });

  it('emits age_attested_at as YYYY-MM-DD string', () => {
    const claims = template.buildClaims({ dateOfBirth: dobExactAge(30) });
    expect(typeof claims['age_attested_at']).toBe('string');
    expect((claims['age_attested_at'] as string)).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it('respects custom ageThresholds', () => {
    const claims = template.buildClaims(
      { dateOfBirth: dobExactAge(20) },
      { ageThresholds: [16, 18, 21] }
    );
    expect(claims['age_over_16']).toBe(true);
    expect(claims['age_over_18']).toBe(true);
    expect(claims['age_over_21']).toBe(false);
  });

  it('rejects non-array ageThresholds', () => {
    expect(() =>
      template.buildClaims({ dateOfBirth: dobExactAge(25) }, { ageThresholds: 18 })
    ).toThrow('Invalid templateOptions');
  });

  it('rejects duplicate ageThresholds', () => {
    expect(() =>
      template.buildClaims({ dateOfBirth: dobExactAge(25) }, { ageThresholds: [18, 18] })
    ).toThrow('Invalid templateOptions');
  });

  it('rejects out-of-range ageThresholds', () => {
    expect(() =>
      template.buildClaims({ dateOfBirth: dobExactAge(25) }, { ageThresholds: [200] })
    ).toThrow('Invalid templateOptions');
  });

  it('throws when dateOfBirth is missing', () => {
    expect(() => template.buildClaims({})).toThrow('requires dateOfBirth');
  });

  it('validateMappings returns error if dateOfBirth mapping is missing', () => {
    const errors = template.validateMappings({});
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toContain('dateOfBirth');
  });

  it('validateMappings returns empty array when mapping is present', () => {
    const errors = template.validateMappings({ dateOfBirth: 'dateOfBirth' });
    expect(errors).toHaveLength(0);
  });
});

// ---- EmployeeCredential ----

describe('EmployeeCredential', () => {
  const template = getTemplate('EmployeeCredential');
  const baseData = {
    given_name: 'Jonas',
    family_name: 'Meyer',
    organization: 'askmi GmbH',
    role: 'Engineer',
    email: 'jonas@example.com',
    dateOfBirth: '1990-01-01',
    address: 'Somewhere 1, Berlin',
  };

  it('never emits email in claims', () => {
    const claims = template.buildClaims(baseData);
    expect(Object.keys(claims)).not.toContain('email');
  });

  it('never emits dateOfBirth in claims', () => {
    const claims = template.buildClaims(baseData);
    expect(Object.keys(claims)).not.toContain('dateOfBirth');
  });

  it('never emits address in claims', () => {
    const claims = template.buildClaims(baseData);
    expect(Object.keys(claims)).not.toContain('address');
  });

  it('emits required fields', () => {
    const claims = template.buildClaims(baseData);
    expect(claims['given_name']).toBe('Jonas');
    expect(claims['family_name']).toBe('Meyer');
    expect(claims['organization']).toBe('askmi GmbH');
    expect(claims['role']).toBe('Engineer');
  });

  it('validateMappings returns errors for missing required fields', () => {
    const errors = template.validateMappings({});
    expect(errors.length).toBeGreaterThan(0);
  });

  it('validateMappings passes with all required fields mapped', () => {
    const errors = template.validateMappings({
      given_name: 'given_name',
      family_name: 'family_name',
      organization: 'organization',
      role: 'role',
    });
    expect(errors).toHaveLength(0);
  });
});

// ---- MembershipCredential ----

describe('MembershipCredential', () => {
  const template = getTemplate('MembershipCredential');

  it('works with only required fields (no name, no email)', () => {
    const claims = template.buildClaims({
      organization: 'CCC',
      membershipType: 'supporter',
    });
    expect(claims['organization']).toBe('CCC');
    expect(claims['membership_type']).toBe('supporter');
  });

  it('never emits email even if provided in holderData', () => {
    const claims = template.buildClaims({
      organization: 'CCC',
      membershipType: 'supporter',
      email: 'member@ccc.de',
    });
    expect(Object.keys(claims)).not.toContain('email');
  });

  it('includes optional memberId when provided', () => {
    const claims = template.buildClaims({
      organization: 'CCC',
      membershipType: 'supporter',
      memberId: 'M-12345',
    });
    expect(claims['member_id']).toBe('M-12345');
  });

  it('validateMappings passes with required fields', () => {
    const errors = template.validateMappings({
      organization: 'organization',
      membershipType: 'membershipType',
    });
    expect(errors).toHaveLength(0);
  });
});

// ---- Registry ----

describe('Registry', () => {
  it('throws a descriptive error for unknown credential type', () => {
    expect(() => getTemplate('UnknownCredential')).toThrow('Unknown credential type');
    expect(() => getTemplate('UnknownCredential')).toThrow('UnknownCredential');
  });

  it('listTemplates includes all registered templates', () => {
    const ids = listTemplates().map(t => t.id);
    expect(ids).toContain('AgeCredential');
    expect(ids).toContain('EmployeeCredential');
    expect(ids).toContain('MembershipCredential');
  });
});
