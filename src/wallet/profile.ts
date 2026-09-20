import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { exportJWK, type KeyLike } from 'jose';
import { loadAttestationPolicy } from './attestation.js';
import { registrationInfo } from './registration.js';
import { getIssuerKeyPair } from '../keys/manager.js';

export type WalletProfile = 'custom' | 'eudi-android';
export function getWalletProfile(): WalletProfile {
  const value = process.env.WALLET_PROFILE ?? 'custom';
  if (value !== 'custom' && value !== 'eudi-android') throw new Error('Unsupported WALLET_PROFILE');
  return value;
}
/** Checks signing material, not membership in an external trust list. */
export async function certificateSigner(role: 'issuer' | 'verifier') {
  const certPath = process.env[role === 'issuer' ? 'EUDI_ISSUER_CERT_CHAIN_PATH' : 'EUDI_VERIFIER_CERT_CHAIN_PATH'];
  if (!certPath) throw new Error('EUDI certificate chain is not configured');
  const blocks = readFileSync(certPath, 'utf8').match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (!blocks?.length || blocks.length > 8) throw new Error('Invalid certificate chain');
  const chain = blocks.map(block => new X509Certificate(block));
  const now = Date.now();
  for (let i = 0; i < chain.length; i++) {
    if (now < Date.parse(chain[i].validFrom) || now >= Date.parse(chain[i].validTo)) throw new Error('Certificate is outside its validity period');
    if (i + 1 < chain.length && (!chain[i + 1].ca || !chain[i].checkIssued(chain[i + 1]) ||
        !chain[i].verify(chain[i + 1].publicKey))) throw new Error('Certificate chain issuer or signature mismatch');
  }
  if (chain[0].ca) throw new Error('A leaf signing certificate is required');
  let privateKey: KeyLike;
  if (role === 'issuer') privateKey = (await getIssuerKeyPair()).privateKey;
  else {
    const keyPath = process.env.EUDI_VERIFIER_KEY_PATH;
    if (!keyPath) throw new Error('EUDI verifier key is not configured');
    privateKey = createPrivateKey(readFileSync(keyPath, 'utf8'));
  }
  const privateJwk = await exportJWK(privateKey);
  const certificateJwk = chain[0].publicKey.export({ format: 'jwk' });
  if (privateJwk.kty !== 'EC' || privateJwk.crv !== 'P-256' ||
      privateJwk.x !== certificateJwk.x || privateJwk.y !== certificateJwk.y) throw new Error('Certificate must match the P-256 signing key');
  const thumbprint = createHash('sha256').update(chain[0].raw).digest('base64url');
  return { privateKey, x5c: chain.map(cert => cert.raw.toString('base64')), thumbprint,
    clientId: 'x509_hash:' + thumbprint };
}
export async function assertWalletProfileReady(issuerUrl: string, format?: string) {
  if (getWalletProfile() !== 'eudi-android') return;
  if (new URL(issuerUrl).protocol !== 'https:' || (format && format !== 'dc+sd-jwt')) throw new Error('EUDI profile requires HTTPS and dc+sd-jwt');
  loadAttestationPolicy();
  await certificateSigner('issuer');
  await certificateSigner('verifier');
  await registrationInfo('issuer');
  await registrationInfo('verifier');
}
