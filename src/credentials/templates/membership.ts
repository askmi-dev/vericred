/**
 * MembershipCredential
 *
 * Source fields: organization, membershipType
 * Optional: memberId, memberSince, memberUntil, given_name, family_name
 *
 * Privacy rule: no email if memberId suffices for identification.
 * No address, no DOB.
 */
import { registerTemplate } from '../registry.js';

registerTemplate({
  id: 'MembershipCredential',
  displayName: 'Membership Credential',
  requiredFields: ['organization', 'membershipType'],
  optionalFields: ['memberId', 'memberSince', 'memberUntil', 'given_name', 'family_name'],
  // First real template enabled on the pre-issuance consent gate (see
  // src/oid4vci/consent.ts). Chosen because no existing test exercises its
  // /offer -> /token -> /credentials flow expecting today's immediate-
  // issuance behavior (unlike EmployeeCredential, which dynamic-issuance
  // test does, and AgeCredential, which is the default fixture reused
  // across 12+ other test call sites).
  requiresConsent: true,

  buildClaims(holderData, options = {}) {
    for (const f of ['organization', 'membershipType']) {
      if (!holderData[f]) throw new Error(`MembershipCredential requires field: ${f}`);
    }

    const claims: Record<string, unknown> = {
      organization: holderData['organization'],
      membership_type: holderData['membershipType'],
    };

    if (holderData['memberId']) claims['member_id'] = holderData['memberId'];
    if (holderData['memberSince']) claims['member_since'] = holderData['memberSince'];

    const memberUntil = (holderData['memberUntil'] as string | undefined)
      ?? (options['memberUntil'] as string | undefined);
    if (memberUntil) claims['member_until'] = memberUntil;

    // Name only if explicitly mapped
    if (holderData['given_name']) claims['given_name'] = holderData['given_name'];
    if (holderData['family_name']) claims['family_name'] = holderData['family_name'];

    return claims;
  },

  validateMappings(fieldMappings) {
    const errors: string[] = [];
    for (const f of ['organization', 'membershipType']) {
      if (!fieldMappings[f]) {
        errors.push(`MembershipCredential requires fieldMappings.${f} -> <source field>`);
      }
    }
    return errors;
  },
});
