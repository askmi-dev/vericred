/**
 * Credential Template Tests — Golden + Invariant
 *
 * Each template section covers:
 *   Golden path: specific input -> expected claims
 *   Forbidden claims: what must never appear in output
 *   Boundary / error cases
 *   validateMappings and validateOptions
 */

import { describe, it, expect } from 'vitest';
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

// ============================================================
// AgeCredential
// ============================================================

describe('AgeCredential', () => {
  const template = getTemplate('AgeCredential');

  // --- Golden path ---
  describe('golden path (25-year-old, default thresholds)', () => {
    const dob = dobExactAge(25);
    it('emits age_over_18 = true', () => {
      const c = template.buildClaims({ dateOfBirth: dob });
      expect(c['age_over_18']).toBe(true);
    });
    it('emits age_over_21 = true', () => {
      const c = template.buildClaims({ dateOfBirth: dob });
      expect(c['age_over_21']).toBe(true);
    });
    it('emits age_attested_at as YYYY-MM-DD', () => {
      const c = template.buildClaims({ dateOfBirth: dob });
      expect(typeof c['age_attested_at']).toBe('string');
      expect(c['age_attested_at'] as string).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });
    it('claim count is exactly 3 (age_over_18, age_over_21, age_attested_at)', () => {
      const c = template.buildClaims({ dateOfBirth: dob });
      // Default thresholds [18,21] → age_over_18, age_over_21, age_attested_at
      expect(Object.keys(c)).toHaveLength(3);
    });
  });

  // --- Forbidden claims ---
  it('FORBIDDEN: never emits dateOfBirth', () => {
    const c = template.buildClaims({ dateOfBirth: dobExactAge(30) });
    expect(Object.keys(c)).not.toContain('dateOfBirth');
  });

  // --- Age boundary ---
  it('17-year-old: age_over_18 = false', () => {
    const c = template.buildClaims({ dateOfBirth: dobExactAge(17) });
    expect(c['age_over_18']).toBe(false);
  });
  it('birthday today (exact 18): age_over_18 = true', () => {
    const c = template.buildClaims({ dateOfBirth: dobExactAge(18) });
    expect(c['age_over_18']).toBe(true);
  });
  it('birthday tomorrow (one day short of 18): age_over_18 = false', () => {
    const c = template.buildClaims({ dateOfBirth: dobOneDayShort(18) });
    expect(c['age_over_18']).toBe(false);
  });

  // --- Custom thresholds ---
  it('respects custom ageThresholds [16, 18, 21]', () => {
    const c = template.buildClaims({ dateOfBirth: dobExactAge(20) }, { ageThresholds: [16, 18, 21] });
    expect(c['age_over_16']).toBe(true);
    expect(c['age_over_18']).toBe(true);
    expect(c['age_over_21']).toBe(false);
  });

  // --- Jurisdiction ---
  it('emits jurisdiction from templateOptions', () => {
    const c = template.buildClaims({ dateOfBirth: dobExactAge(25) }, { jurisdiction: 'AT' });
    expect(c['jurisdiction']).toBe('AT');
  });
  it('omits jurisdiction when not set', () => {
    const c = template.buildClaims({ dateOfBirth: dobExactAge(25) });
    expect(Object.keys(c)).not.toContain('jurisdiction');
  });

  // --- DOB validation ---
  it('rejects missing dateOfBirth', () => {
    expect(() => template.buildClaims({})).toThrow('requires dateOfBirth');
  });
  it('rejects wrong format (DD.MM.YYYY)', () => {
    expect(() => template.buildClaims({ dateOfBirth: '01.01.1990' })).toThrow('Invalid dateOfBirth format');
  });
  it('rejects future dateOfBirth', () => {
    expect(() => template.buildClaims({ dateOfBirth: '2099-01-01' })).toThrow('future');
  });
  it('rejects unrealistic dateOfBirth (>130 years ago)', () => {
    expect(() => template.buildClaims({ dateOfBirth: '1880-01-01' })).toThrow('130 years');
  });
  it('rejects invalid calendar date (Feb 30)', () => {
    expect(() => template.buildClaims({ dateOfBirth: '2000-02-30' })).toThrow('Invalid dateOfBirth');
  });

  // --- validateOptions ---
  it('validateOptions: valid config returns []', () => {
    expect(template.validateOptions?.({ ageThresholds: [18, 21] })).toHaveLength(0);
  });
  it('validateOptions: non-array ageThresholds', () => {
    const errors = template.validateOptions?.({ ageThresholds: 18 }) ?? [];
    expect(errors.length).toBeGreaterThan(0);
  });
  it('validateOptions: duplicate thresholds', () => {
    const errors = template.validateOptions?.({ ageThresholds: [18, 18] }) ?? [];
    expect(errors.length).toBeGreaterThan(0);
  });
  it('validateOptions: out-of-range threshold (>130)', () => {
    const errors = template.validateOptions?.({ ageThresholds: [200] }) ?? [];
    expect(errors.length).toBeGreaterThan(0);
  });
  it('validateOptions: too many thresholds (>10)', () => {
    const errors = template.validateOptions?.({ ageThresholds: [1,2,3,4,5,6,7,8,9,10,11] }) ?? [];
    expect(errors.length).toBeGreaterThan(0);
  });

  // --- validateMappings ---
  it('validateMappings: missing dateOfBirth mapping', () => {
    const errors = template.validateMappings({});
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toContain('dateOfBirth');
  });
  it('validateMappings: correct mapping returns []', () => {
    expect(template.validateMappings({ dateOfBirth: 'dateOfBirth' })).toHaveLength(0);
  });
});

// ============================================================
// EmployeeCredential
// ============================================================

describe('EmployeeCredential', () => {
  const template = getTemplate('EmployeeCredential');

  const goldenInput = {
    given_name: 'Jonas',
    family_name: 'Meyer',
    organization: 'askmi GmbH',
    role: 'Engineer',
    department: 'Platform',
    employeeId: 'EMP-0042',
    // fields that must NEVER appear in claims:
    email: 'jonas@askmi.dev',
    dateOfBirth: '1990-06-01',
    address: 'Musterstr. 1, Berlin',
  };

  it('golden: emits given_name', () => {
    expect(template.buildClaims(goldenInput)['given_name']).toBe('Jonas');
  });
  it('golden: emits family_name', () => {
    expect(template.buildClaims(goldenInput)['family_name']).toBe('Meyer');
  });
  it('golden: emits organization', () => {
    expect(template.buildClaims(goldenInput)['organization']).toBe('askmi GmbH');
  });
  it('golden: emits role', () => {
    expect(template.buildClaims(goldenInput)['role']).toBe('Engineer');
  });
  it('golden: emits department', () => {
    expect(template.buildClaims(goldenInput)['department']).toBe('Platform');
  });
  it('golden: emits employee_id (snake_case)', () => {
    expect(template.buildClaims(goldenInput)['employee_id']).toBe('EMP-0042');
  });

  // --- Forbidden ---
  it('FORBIDDEN: never emits email', () => {
    expect(Object.keys(template.buildClaims(goldenInput))).not.toContain('email');
  });
  it('FORBIDDEN: never emits dateOfBirth', () => {
    expect(Object.keys(template.buildClaims(goldenInput))).not.toContain('dateOfBirth');
  });
  it('FORBIDDEN: never emits address', () => {
    expect(Object.keys(template.buildClaims(goldenInput))).not.toContain('address');
  });

  // --- Errors ---
  it('throws when required field is missing', () => {
    expect(() => template.buildClaims({ given_name: 'X', family_name: 'Y', organization: 'Z' }))
      .toThrow('requires field: role');
  });

  // --- validateMappings ---
  it('validateMappings: missing all required fields', () => {
    expect(template.validateMappings({}).length).toBeGreaterThan(0);
  });
  it('validateMappings: all required fields mapped', () => {
    expect(template.validateMappings({
      given_name: 'given_name', family_name: 'family_name',
      organization: 'organization', role: 'role',
    })).toHaveLength(0);
  });
});

// ============================================================
// MembershipCredential
// ============================================================

describe('MembershipCredential', () => {
  const template = getTemplate('MembershipCredential');

  it('golden (minimal): works with only organization + membershipType', () => {
    const c = template.buildClaims({ organization: 'CCC', membershipType: 'supporter' });
    expect(c['organization']).toBe('CCC');
    expect(c['membership_type']).toBe('supporter');
    expect(Object.keys(c)).toHaveLength(2);
  });

  it('golden (full): includes optional fields when provided', () => {
    const c = template.buildClaims({
      organization: 'CCC',
      membershipType: 'supporter',
      memberId: 'M-1234',
      memberSince: '2020-01-01',
      memberUntil: '2027-12-31',
      given_name: 'Ada',
      family_name: 'Lovelace',
    });
    expect(c['member_id']).toBe('M-1234');
    expect(c['member_since']).toBe('2020-01-01');
    expect(c['member_until']).toBe('2027-12-31');
    expect(c['given_name']).toBe('Ada');
    expect(c['family_name']).toBe('Lovelace');
  });

  it('FORBIDDEN: never emits email even if present in holderData', () => {
    const c = template.buildClaims({
      organization: 'CCC',
      membershipType: 'supporter',
      email: 'member@ccc.de',
    });
    expect(Object.keys(c)).not.toContain('email');
  });

  it('omits given_name and family_name when not mapped (privacy by default)', () => {
    const c = template.buildClaims({ organization: 'CCC', membershipType: 'supporter' });
    expect(Object.keys(c)).not.toContain('given_name');
    expect(Object.keys(c)).not.toContain('family_name');
  });

  it('throws when organization is missing', () => {
    expect(() => template.buildClaims({ membershipType: 'supporter' }))
      .toThrow('requires field: organization');
  });

  it('validateMappings: requires organization and membershipType', () => {
    const errors = template.validateMappings({});
    expect(errors.some(e => e.includes('organization'))).toBe(true);
    expect(errors.some(e => e.includes('membershipType'))).toBe(true);
  });

  it('validateMappings: passes with required fields', () => {
    expect(template.validateMappings({ organization: 'organization', membershipType: 'membershipType' }))
      .toHaveLength(0);
  });
});

// ============================================================
// Registry
// ============================================================

describe('Registry', () => {
  it('unknown type throws with type name and available types', () => {
    expect(() => getTemplate('UnknownCredential')).toThrow('UnknownCredential');
    expect(() => getTemplate('UnknownCredential')).toThrow('Available:');
  });

  it('listTemplates includes all three built-in templates', () => {
    const ids = listTemplates().map(t => t.id);
    expect(ids).toContain('AgeCredential');
    expect(ids).toContain('EmployeeCredential');
    expect(ids).toContain('MembershipCredential');
  });

  it('each template in listTemplates has id, displayName, requiredFields', () => {
    for (const t of listTemplates()) {
      expect(typeof t.id).toBe('string');
      expect(typeof t.displayName).toBe('string');
      expect(Array.isArray(t.requiredFields)).toBe(true);
    }
  });
});
