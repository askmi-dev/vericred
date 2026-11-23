/**
 * Issuer URL self-check.
 *
 * Everything a wallet uses comes from `issuer.url`: the credential_issuer in
 * metadata, the credential endpoint, the status list URIs, the x5c SAN. OID4VCI
 * requires credential_issuer to be identical to the URL the metadata was
 * fetched from. If ISSUER_URL is wrong for this deployment (e.g. a Railway PR
 * environment that inherited production's value), a strict wallet rejects the
 * issuer and a lenient one sends issuance to the other deployment.
 *
 * Advisory only: it logs and reports on /health, it never blocks. A reverse
 * proxy that rewrites Host must not make VeriCred unusable, and the observed
 * origin comes from client-supplied headers.
 */

export type IssuerUrlStatus =
  | { status: 'unchecked'; configured: string }
  | { status: 'ok'; configured: string }
  | { status: 'mismatch'; configured: string; observed: string; lastSeen: string; hint: string };

// Hostname or [IPv6], optional port. Anything else is ignored, not reported.
const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*|\[[0-9a-f:.]+\])(?::\d{1,5})?$/i;
const MAX_LOGGED = 20;

type Headers = Record<string, string | string[] | undefined>;

/** The origin a request was addressed to, as the client saw it. */
export function observedOrigin(headers: Headers, protocol: string): string | null {
  const host = first(headers['x-forwarded-host']) ?? first(headers['host']);
  if (!host || !HOST.test(host)) return null;
  const fwdProto = first(headers['x-forwarded-proto'])?.toLowerCase();
  const proto = fwdProto === 'http' || fwdProto === 'https' ? fwdProto : protocol;
  try {
    return new URL(`${proto}://${host}`).origin;
  } catch {
    return null;
  }
}

function first(v: string | string[] | undefined): string | undefined {
  const s = Array.isArray(v) ? v[0] : v;
  return s?.split(',')[0]?.trim() || undefined;
}

const originOf = (url: string) => { try { return new URL(url).origin; } catch { return url; } };

let state: { configured: string; ok: boolean; mismatch?: { observed: string; lastSeen: string } } | null = null;
const logged = new Set<string>();

/** Record a metadata request. Returns true if it disagreed with issuer.url. */
export function noteMetadataRequest(configuredUrl: string, observed: string | null): boolean {
  if (!observed) return false;
  if (!state || state.configured !== configuredUrl) {
    state = { configured: configuredUrl, ok: false };
    logged.clear();
  }
  if (observed === originOf(configuredUrl)) {
    state.ok = true;
    return false;
  }
  state.mismatch = { observed, lastSeen: new Date().toISOString() };
  if (!logged.has(observed) && logged.size < MAX_LOGGED) {
    logged.add(observed);
    console.warn(`[issuer-url] Wallet metadata was requested at ${observed}, but issuer.url is ${configuredUrl}. `
      + `Wallets will reject this issuer or send issuance to ${originOf(configuredUrl)}. ${HINT}`);
  }
  return true;
}

const HINT = 'Set ISSUER_URL to this deployment\'s public https URL (on Railway: https://${{RAILWAY_PUBLIC_DOMAIN}}), '
  + 'or ignore this if the request came through an alias that wallets never use.';

export function getIssuerUrlStatus(configuredUrl: string): IssuerUrlStatus {
  if (!state || state.configured !== configuredUrl) return { status: 'unchecked', configured: configuredUrl };
  if (state.mismatch) return { status: 'mismatch', configured: configuredUrl, ...state.mismatch, hint: HINT };
  return { status: 'ok', configured: configuredUrl };
}

/**
 * Startup check that needs no request: a platform that announces its public
 * domain (Railway) can be compared with issuer.url right away.
 */
export function startupIssuerUrlWarning(configuredUrl: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const domain = env['RAILWAY_PUBLIC_DOMAIN'];
  if (!domain) return null;
  let host: string;
  try { host = new URL(configuredUrl).host; } catch { return `[issuer-url] issuer.url "${configuredUrl}" is not a valid URL.`; }
  if (host === domain) return null;
  return `[issuer-url] This Railway deployment's public domain is ${domain}, but issuer.url is ${configuredUrl}`
    + `${env['RAILWAY_ENVIRONMENT_NAME'] ? ` (environment: ${env['RAILWAY_ENVIRONMENT_NAME']})` : ''}. `
    + 'If wallets reach this deployment at ' + domain + ', set ISSUER_URL=https://${{RAILWAY_PUBLIC_DOMAIN}}. '
    + 'If issuer.url is your custom domain for this deployment, ignore this.';
}

type Fetch = (url: string, init?: { signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * Before requesting a certificate: does the deployment at issuer.url sign with
 * THIS key? A CSR binds a key to a URL; if issuer.url points at another
 * deployment (inherited ISSUER_URL), the certificate would certify a key that
 * URL never uses. Returns problems found; empty means it matches.
 */
export async function verifyIssuerUrlServesKey(
  issuerUrl: string,
  key: { kid: string; x?: string; y?: string },
  fetchImpl: Fetch = fetch as unknown as Fetch,
): Promise<string[]> {
  const base = issuerUrl.replace(/\/+$/, '');
  const get = async (path: string): Promise<unknown> => {
    const url = new URL(path, base + '/').toString();
    let res;
    try {
      res = await fetchImpl(url, { signal: AbortSignal.timeout(10_000) });
    } catch (e) {
      throw new Error(`${url} is not reachable (${(e as Error).message})`);
    }
    if (!res.ok) throw new Error(`${url} answered HTTP ${res.status}`);
    return res.json();
  };

  const problems: string[] = [];
  try {
    const meta = await get('/.well-known/openid-credential-issuer') as { credential_issuer?: string };
    if (meta.credential_issuer?.replace(/\/+$/, '') !== base) {
      problems.push(`the metadata at ${base} names credential_issuer ${meta.credential_issuer ?? '(none)'}, not ${base}`);
    }
    const did = await get('/.well-known/did.json') as { verificationMethod?: Array<{ publicKeyJwk?: { kid?: string; x?: string; y?: string } }> };
    const served = (did.verificationMethod ?? []).map(m => m.publicKeyJwk);
    if (!served.some(j => j?.kid === key.kid && j.x === key.x && j.y === key.y)) {
      problems.push(`the deployment at ${base} does not publish this key (kid ${key.kid}). `
        + 'issuer.url points at a different deployment, or that deployment has another DATA_DIR');
    }
  } catch (e) {
    problems.push((e as Error).message);
  }
  return problems;
}

/** Test hook. */
export function resetIssuerUrlCheck(): void {
  state = null;
  logged.clear();
}
