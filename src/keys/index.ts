/**
 * Key provider factory — selects the backend from configuration, fail-closed
 * on unknown or missing provider types.
 *
 * Usage: const provider = await getKeyProvider();
 * Read keys.provider from vericred.config.json (optional; default "file").
 */
import { readFileSync, existsSync } from 'fs';
import { FileKeyProvider } from './file-provider.js';
import { KmsKeyProvider } from './kms-provider.js';
import type { KeyProvider, KeyProviderType } from './provider.js';

const CONFIG_PATH = process.env.VERICRED_CONFIG ?? './vericred.config.json';

interface ConfigShape {
  keys?: { provider?: string };
}

let cached: KeyProvider | null = null;

export async function getKeyProvider(): Promise<KeyProvider> {
  if (cached) return cached;

  let providerType: string = 'file';
  if (existsSync(CONFIG_PATH)) {
    const config = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8')) as ConfigShape;
    providerType = config.keys?.provider ?? 'file';
  }

  cached = createProvider(providerType as KeyProviderType);
  console.log(`[keys] Key provider active: ${cached.name}`);
  return cached;
}

function createProvider(type: KeyProviderType): KeyProvider {
  switch (type) {
    case 'file':
      return new FileKeyProvider();
    case 'kms':
      // Constructor fails closed until the adapter is implemented.
      return new KmsKeyProvider(undefined);
    default: {
      // Exhaustive fail-closed: unknown types never fall back silently.
      throw new Error(
        `[keys] Unknown key provider "${type}". Supported: "file", "kms". Refusing to start.`
      );
    }
  }
}

/** Test hook: reset the cached provider between tests. */
export function resetKeyProviderCache(): void {
  cached = null;
}

export type { KeyProvider, KeyProviderType } from './provider.js';
