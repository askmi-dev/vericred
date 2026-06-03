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

/**
 * Exact UTC-based age calculation.
 * Handles birthday boundaries correctly — no floating-point year approximation.
 */
function ageAt(dob: string, at = new Date()): number {
  const birth = new Date(dob + 'T00:00:00Z');
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
      if (unique.size !== thresholds.length) {
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

  buildClaims(holderData, options = {}) {
    const dob = holderData['dateOfBirth'] as string | undefined;
    if (!dob) throw new Error('AgeCredential requires dateOfBirth');

    const optErrors = validateAgeOptions(options);
    if (optErrors.length > 0) throw new Error('Invalid templateOptions: ' + optErrors.join('; '));

    const ageYears = ageAt(dob);
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
