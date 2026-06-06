/**
 * Privacy Utility: PII-masking helper functions for administrative API payloads.
 * Masks personal details such as emails, names, and passwords.
 */

export function maskEmail(email: unknown): string {
  if (typeof email !== 'string') return '***';
  const parts = email.split('@');
  if (parts.length !== 2) return '***';
  const [local, domain] = parts;
  if (local.length <= 2) {
    return local.charAt(0) + '***@' + domain;
  }
  return local.slice(0, 2) + '***@' + domain;
}

export function maskName(name: unknown): string {
  if (typeof name !== 'string') return '';
  const trimmed = name.trim();
  if (trimmed.length === 0) return '';
  const parts = trimmed.split(/\s+/);
  return parts.map(part => {
    if (part.length <= 2) return part.charAt(0) + '***';
    return part.slice(0, 2) + '***';
  }).join(' ');
}

export function maskHolderRecord(holder: Record<string, unknown>): Record<string, unknown> {
  const masked = { ...holder };
  if (masked['email']) masked['email'] = maskEmail(masked['email']);
  if (masked['firstName']) masked['firstName'] = maskName(masked['firstName']);
  if (masked['lastName']) masked['lastName'] = maskName(masked['lastName']);
  if (masked['givenName']) masked['givenName'] = maskName(masked['givenName']);
  if (masked['familyName']) masked['familyName'] = maskName(masked['familyName']);
  if (masked['dateOfBirth']) masked['dateOfBirth'] = '****-**-**';
  if (masked['date_of_birth']) masked['date_of_birth'] = '****-**-**';
  
  // Protect passwords absolutely from leaking
  delete masked['defaultPassword'];
  delete masked['customPassword'];
  return masked;
}

export function maskCredentialRecord(cred: Record<string, unknown>): Record<string, unknown> {
  const masked = { ...cred };
  if (masked['holderEmail']) {
    masked['holderEmail'] = maskEmail(masked['holderEmail']);
  }
  return masked;
}
