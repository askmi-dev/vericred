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

registerTemplate({
  id: 'AgeCredential',
  displayName: 'Age Verification Credential',
  requiredFields: ['dateOfBirth'],
  optionalFields: ['jurisdiction'],

  buildClaims(holderData, options = {}) {
    const dob = holderData['dateOfBirth'] as string | undefined;
    if (!dob) throw new Error('AgeCredential requires dateOfBirth');

    const birthDate = new Date(dob);
    const now = new Date();
    const ageMs = now.getTime() - birthDate.getTime();
    const ageYears = Math.floor(ageMs / (365.25 * 24 * 3600 * 1000));

    const thresholds = (options['ageThresholds'] as number[] | undefined) ?? [18, 21];

    const claims: Record<string, unknown> = {};

    for (const t of thresholds) {
      claims[`age_over_${t}`] = ageYears >= t;
    }

    claims['age_attested_at'] = now.toISOString().slice(0, 10);

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
