/**
 * AgeCredential
 *
 * Source field: dateOfBirth (ISO date string: YYYY-MM-DD)
 * Issued claims:
 *   - age_over_{N}: boolean for each configured threshold (default: 18, 21)
 *   - age_attested_at: ISO date of credential issuance
 *   - jurisdiction: optional string (e.g. "EU", "AT", "DE")
 *
 * Privacy rule: dateOfBirth is NEVER included in the issued claims.
 * Only predicates (age_over_N) are disclosed.
 */
import { registerTemplate } from '../registry.js';

const DOB_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Strict DOB validation.
 * Rejects: non-string, wrong format, invalid calendar date, future dates, unrealistic dates (>130y).
 */
function parseDob(dob: unknown): Date {
  if (dob === undefined || dob === null) {
    throw new Error('AgeCredential requires dateOfBirth');
  }
  if (typeof dob !== 'string' || !DOB_PATTERN.test(dob)) {
    throw new Error(`Invalid dateOfBirth format: "${dob}" — expected YYYY-MM-DD`);
  }
  const birth = new Date(dob + 'T00:00:00Z');
  if (isNaN(birth.getTime())) {
    throw new Error(`Invalid dateOfBirth value: "${dob}" — not a valid calendar date`);
  }
  // Detect JS date overflow (e.g. Feb 30 → Mar 1): re-check parsed date parts
  const [year, month, day] = dob.split('-').map(Number) as [number, number, number];
  if (
    birth.getUTCFullYear() !== year ||
    birth.getUTCMonth() + 1 !== month ||
    birth.getUTCDate() !== day
  ) {
    throw new Error(`Invalid dateOfBirth value: "${dob}" — not a valid calendar date`);
  }
  const now = new Date();
  if (birth > now) {
    throw new Error(`Invalid dateOfBirth: "${dob}" — date is in the future`);
  }
  const maxAge = new Date(Date.UTC(now.getUTCFullYear() - 130, now.getUTCMonth(), now.getUTCDate()));
  if (birth < maxAge) {
    throw new Error(`Invalid dateOfBirth: "${dob}" — age would exceed 130 years`);
  }
  return birth;
}

/**
 * Exact UTC-based age calculation.
 * Handles birthday boundaries correctly — no floating-point year approximation.
 */
function ageAt(birth: Date, at = new Date()): number {
  let age = at.getUTCFullYear() - birth.getUTCFullYear();
  const monthDiff = at.getUTCMonth() - birth.getUTCMonth();
  if (monthDiff < 0 || (monthDiff === 0 && at.getUTCDate() < birth.getUTCDate())) age--;
  return age;
}

/**
 * Validate templateOptions for AgeCredential.
 * Returns array of error strings (empty = valid).
 */
function validateAgeOptions(options: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const thresholds = options['ageThresholds'];
  if (thresholds !== undefined) {
    if (!Array.isArray(thresholds)) {
      errors.push('templateOptions.ageThresholds must be an array of integers');
    } else {
      if (thresholds.length === 0) errors.push('templateOptions.ageThresholds must not be empty');
      if (thresholds.length > 10) errors.push('templateOptions.ageThresholds must have at most 10 entries');
      for (const t of thresholds) {
        if (!Number.isInteger(t) || t < 0 || t > 130) {
          errors.push(`templateOptions.ageThresholds entry "${t}" must be an integer between 0 and 130`);
        }
      }
      const unique = new Set(thresholds);
      if (unique.size !== (thresholds as unknown[]).length) {
        errors.push('templateOptions.ageThresholds must not contain duplicates');
      }
    }
  }
  const jurisdiction = options['jurisdiction'];
  if (jurisdiction !== undefined && typeof jurisdiction !== 'string') {
    errors.push('templateOptions.jurisdiction must be a string');
  }
  return errors;
}

registerTemplate({
  id: 'AgeCredential',
  displayName: 'Age Verification Credential',
  requiredFields: ['dateOfBirth'],
  optionalFields: ['jurisdiction'],

  validateOptions: validateAgeOptions,

  buildClaims(holderData, options = {}) {
    const birth = parseDob(holderData['dateOfBirth']);
    const ageYears = ageAt(birth);
    const thresholds = (options['ageThresholds'] as number[] | undefined) ?? [18, 21];

    const claims: Record<string, unknown> = {};

    for (const t of thresholds) {
      claims[`age_over_${t}`] = ageYears >= t;
    }

    claims['age_attested_at'] = new Date().toISOString().slice(0, 10);

    const jurisdiction = (options['jurisdiction'] as string | undefined)
      ?? (holderData['jurisdiction'] as string | undefined);
    if (jurisdiction) claims['jurisdiction'] = jurisdiction;

    // Explicit: dateOfBirth is NOT emitted
    return claims;
  },

  validateMappings(fieldMappings) {
    const errors: string[] = [];
    if (!fieldMappings['dateOfBirth']) {
      errors.push('AgeCredential requires fieldMappings.dateOfBirth -> <source field>');
    }
    return errors;
  },
});
