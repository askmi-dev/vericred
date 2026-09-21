import type { VeriCredConfig } from './types.js';

/** Resolve the same explicit template policy for discovery, offers, and issuance. */
export function resolveTemplateConfig(config: VeriCredConfig, type: string): {
  fieldMappings: Record<string, string>; templateOptions: Record<string, unknown>;
} {
  return structuredClone({
    fieldMappings: config.templateMappings?.[type]
      ?? (type === config.credential.type ? config.fieldMappings : {}),
    templateOptions: config.templateOptionsByType?.[type]
      ?? (type === config.credential.type ? config.templateOptions ?? {} : {}),
  });
}

/** Preserve the previous active template's policy when changing the active selection. */
export function selectTemplate(config: VeriCredConfig, type: string, fieldMappings: Record<string, string>): void {
  const previousType = config.credential.type;
  const previous = resolveTemplateConfig(config, previousType);
  const selected = resolveTemplateConfig(config, type);
  config.templateMappings = { ...config.templateMappings, [previousType]: previous.fieldMappings, [type]: structuredClone(fieldMappings) };
  config.templateOptionsByType = { ...config.templateOptionsByType, [previousType]: previous.templateOptions, [type]: selected.templateOptions };
  config.credential.type = type;
  config.fieldMappings = structuredClone(fieldMappings);
  config.templateOptions = selected.templateOptions;
}
