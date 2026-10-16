/**
 * FileKeyProvider — wraps the existing key manager (JSON-file keystore).
 *
 * This is the default and preserves the current behaviour exactly:
 * keys live under DATA_DIR (default ./keys), rotation archives to key-history.json.
 * Dev/demo grade only — see SECURITY.md before any production use.
 */
import { SignJWT, importJWK } from 'jose';
import type { JWK, KeyLike } from 'jose';
import { getIssuerKeyPair, rotateIssuerKeyPair, getAllPublicKeys } from './manager.js';
import type { KeyProvider } from './provider.js';

export class FileKeyProvider implements KeyProvider {
  readonly name = 'file';

  private async active(): Promise<{ privateKey: KeyLike; publicKey: KeyLike; kid: string }> {
    return getIssuerKeyPair();
  }

  async getKid(): Promise<string> {
    return (await this.active()).kid;
  }

  async getPublicJwk(): Promise<JWK> {
    const pair = await this.active();
    // The manager stores JWKs; re-export via jose for a consistent type.
    return (await importJWK(await toJwk(pair.publicKey, pair.kid), 'ES256')) as unknown as JWK;
  }

  async listPublicKeys(): Promise<Array<{ publicKey: JWK; kid: string }>> {
    return getAllPublicKeys();
  }

  async sign(payload: string): Promise<string> {
    const pair = await this.active();
    return new SignJWT(JSON.parse(payload) as Record<string, unknown>)
      .setProtectedHeader({ alg: 'ES256', kid: pair.kid })
      .sign(pair.privateKey);
  }

  async rotate(): Promise<string> {
    const rotated = await rotateIssuerKeyPair();
    return rotated.kid;
  }
}

/**
 * The manager keeps JWK JSON in files; publicKey KeyLike objects obtained via
 * importJWK can be re-exported. Simplest correct path: re-import via the stored
 * file is unnecessary — exportJWK works on KeyLike.
 */
async function toJwk(key: KeyLike, _kid: string): Promise<JWK> {
  const { exportJWK } = await import('jose');
  return exportJWK(key);
}
