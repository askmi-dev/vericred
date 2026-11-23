import { describe, it, expect } from 'vitest';
import { getSessionId } from '../auth.js';
import type { Request } from 'express';

describe('auth middleware', () => {
  describe('parseCookies', () => {
    it('ignores malformed uri components', () => {
      // getSessionId uses the internal parseCookies to parse the cookie header.
      // %C2 is an invalid URI component in decodeURIComponent, so it will throw an error
      // testing the catch block.
      const req = {
        headers: {
          cookie: 'admin_session=valid_session_id; bad_cookie=%C2'
        }
      } as Request;

      // The valid cookie should still be parsed, and the malformed one should be ignored
      expect(getSessionId(req)).toBe('valid_session_id');
    });

    it('ignores entirely malformed cookies', () => {
      // Also check cookies missing an equals sign are ignored as expected
      const req = {
        headers: {
          cookie: 'admin_session=valid_session_id; %C2'
        }
      } as Request;

      expect(getSessionId(req)).toBe('valid_session_id');
    });
  });
});
