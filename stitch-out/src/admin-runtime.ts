export interface RuntimeReadiness {
    generatedAt: string;
    issuer: { name: string; url: string; did: string };
    walletProfile: string;
    source: { type: string; configured: boolean };
    credentials: { type: string; format: string; vct: string; configured: boolean }[];
    configurationReady: boolean;
    releaseAccepted: false;
    checks: { id: string; label: string; status: 'ready' | 'blocked' | 'not_verified' | 'not_applicable'; basis: string; detail: string }[];
}

export async function readJson<T>(url: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000), ...init });
    if (response.redirected || response.status === 401 || response.status === 403) throw new Error('Your session has expired. Sign in again.');
    if (!response.ok) throw new Error(`Request unavailable (${response.status}). Retry or check the gateway.`);
    if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('The gateway returned an unexpected response. Sign in again if your session expired.');
    return response.json();
}

let readiness: Promise<RuntimeReadiness> | undefined;
export function runtimeReadiness(refresh = false): Promise<RuntimeReadiness> {
    if (!readiness || refresh) readiness = readJson<RuntimeReadiness>('/admin/api/readiness').then(data => { window.dispatchEvent(new CustomEvent('vericred:readiness-updated', { detail: data })); return data; });
    return readiness;
}

export const statusLabels = { ready: 'Ready', blocked: 'Action needed', not_verified: 'Not verified', not_applicable: 'Not applicable' };

export function element<K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = ''): HTMLElementTagNameMap[K] {
    const node = document.createElement(tag);
    node.textContent = text;
    if (className) node.className = className;
    return node;
}

export function formatTime(value: unknown): string {
    const date = new Date(String(value ?? ''));
    return Number.isFinite(date.getTime()) ? date.toLocaleString() : 'Unknown';
}
