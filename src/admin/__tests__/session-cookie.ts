/**
 * Extracts `admin_session=<token>` from a login response's Set-Cookie header.
 * Throws with a clear message if the cookie is missing, so a broken login
 * fails the test instead of sending an empty or undefined Cookie header.
 */
export function sessionCookieFrom(setCookie: string | null): string {
  const part = setCookie
    ?.split(',')
    .find(c => c.includes('admin_session='))
    ?.split(';')[0]
    ?.trim();
  if (!part || part === 'admin_session=') {
    throw new Error(`login response did not set an admin_session cookie (Set-Cookie: ${setCookie ?? 'none'})`);
  }
  return part;
}
