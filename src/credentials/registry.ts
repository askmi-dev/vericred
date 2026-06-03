/**
 * Credential Template Registry
 *
 * Each template defines:
 *   - id / displayName
 *   - requiredFields: source fields that must exist in holderData
 *   - optionalFields: source fields used if present
 *   - buildClaims(): maps holderData -> VC claims (no unnecessary raw PII)
 *   - validateMappings(): checks config.fieldMappings covers requiredFields
 *
 * issuer.ts calls getTemplate(config.credential.type) and uses buildClaims().
 */

export interface CredentialTemplate {
  id: string;
  displayName: string;
  requiredFields: string[];
  optionalFields: string[];
  buildClaims(
    holderData: Record<string, unknown>,
    options?: Record<string, unknown>
  ): Record<string, unknown>;
  validateMappings(fieldMappings: Record<string, string>): string[];
}

const registry = new Map<string, CredentialTemplate>();

export function registerTemplate(template: CredentialTemplate): void {
  registry.set(template.id, template);
}

export function getTemplate(type: string): CredentialTemplate {
  const t = registry.get(type);
  if (!t) throw new Error(
    `Unknown credential type: "${type}". Available: ${[...registry.keys()].join(', ')}`
  );
  return t;
}

export function listTemplates(): { id: string; displayName: string; requiredFields: string[] }[] {
  return [...registry.values()].map(t => ({
    id: t.id,
    displayName: t.displayName,
    requiredFields: t.requiredFields,
  }));
}
