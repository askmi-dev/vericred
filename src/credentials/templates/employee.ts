/**
 * EmployeeCredential
 *
 * Source fields: given_name, family_name, organization, role
 * Optional: department, employeeId, validUntil
 *
 * Privacy rule: no private address, no DOB, no personal email.
 * Only professional identity claims are issued.
 */
import { registerTemplate } from '../registry.js';

registerTemplate({
  id: 'EmployeeCredential',
  displayName: 'Employee Identity Credential',
  requiredFields: ['given_name', 'family_name', 'organization', 'role'],
  optionalFields: ['department', 'employeeId', 'validUntil'],

  buildClaims(holderData, options = {}) {
    for (const f of ['given_name', 'family_name', 'organization', 'role']) {
      if (!holderData[f]) throw new Error(`EmployeeCredential requires field: ${f}`);
    }

    const claims: Record<string, unknown> = {
      given_name: holderData['given_name'],
      family_name: holderData['family_name'],
      organization: holderData['organization'],
      role: holderData['role'],
    };

    if (holderData['department']) claims['department'] = holderData['department'];
    if (holderData['employeeId']) claims['employee_id'] = holderData['employeeId'];

    // validUntil: from data, options, or default 1 year
    const validUntil = (holderData['validUntil'] as string | undefined)
      ?? (options['validUntil'] as string | undefined)
      ?? new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10);
    claims['valid_until'] = validUntil;

    return claims;
  },

  validateMappings(fieldMappings) {
    const errors: string[] = [];
    for (const f of ['given_name', 'family_name', 'organization', 'role']) {
      if (!fieldMappings[f]) {
        errors.push(`EmployeeCredential requires fieldMappings.${f} -> <source field>`);
      }
    }
    return errors;
  },
});
