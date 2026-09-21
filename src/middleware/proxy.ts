import { isIP } from 'node:net';

/** Only explicitly configured network peers may supply forwarding headers. No hop-count or trust-all mode. */
export function trustedProxies(value = process.env.TRUSTED_PROXY_CIDRS): false | string[] {
  if (!value?.trim()) return false;
  const entries = value.split(',').map(v => v.trim());
  for (const entry of entries) {
    const [address, prefix, ...extra] = entry.split('/');
    const version = isIP(address);
    if (!version || extra.length || (prefix !== undefined &&
        (!/^\d+$/.test(prefix) || Number(prefix) < 1 || Number(prefix) > (version === 4 ? 32 : 128)))) {
      throw new Error('TRUSTED_PROXY_CIDRS must contain explicit IP addresses or nonzero CIDRs');
    }
  }
  return entries;
}
