/** Escape text and quoted attribute values used in HTML templates. */
export function escapeHtml(value: unknown): string {
    const entities: Record<string, string> = {
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    };
    return String(value ?? '').replace(/[&<>"']/g, char => entities[char]);
}

/** Obtain a separate one-use CSRF token for every write, including retries. */
export async function adminMutation(url: string, init: RequestInit): Promise<Response> {
    const handshake = await fetch('/admin/api/csrf-handshake', {
        credentials: 'same-origin', cache: 'no-store'
    });
    if (!handshake.ok) throw new Error('Your session has expired. Sign in again before continuing.');
    const { csrfToken } = await handshake.json();
    if (typeof csrfToken !== 'string' || !csrfToken) {
        throw new Error('Could not authorize this action. Please try again.');
    }
    const headers = new Headers(init.headers);
    headers.set('x-csrf-token', csrfToken);
    return fetch(url, { ...init, headers, credentials: 'same-origin' });
}
