import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { loadRestConnector } from '../rest.js';

describe('REST API Connector', () => {
  const pseudonymSecret = 'test_pseudonym_secret_32_bytes_long_!!!';

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('correctly formats url and sends fetch request with authorization headers', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        id: 'user_123',
        name: 'Jane Doe',
        email: 'jane@example.com',
      }),
    });
    vi.stubGlobal('fetch', mockFetch);

    const connector = loadRestConnector(
      {
        endpoint: 'https://api.example.com/students/{id}/details',
        authHeader: 'Bearer my_secret_token_abc123',
      },
      pseudonymSecret
    );

    const result = await connector.lookup('jane@example.com');

    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.example.com/students/jane%40example.com/details',
      {
        headers: {
          'Accept': 'application/json',
          'Authorization': 'Bearer my_secret_token_abc123',
        },
      }
    );

    expect(result).not.toBeNull();
    expect(result?.['email']).toBe('jane@example.com');
    expect(result?.['name']).toBe('Jane Doe');
    expect(result?.['id']).toBe('user_123');
    expect(result?.['defaultPassword']).toBeDefined();
    expect(result?.['_source']).toBe('rest');
  });

  it('returns null if response is not ok', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
    });
    vi.stubGlobal('fetch', mockFetch);

    const connector = loadRestConnector(
      {
        endpoint: 'https://api.example.com/students/{id}',
      },
      pseudonymSecret
    );

    const result = await connector.lookup('non_existent');
    expect(result).toBeNull();
  });

  it('logs error and returns null on fetch exception', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('Network offline'));
    vi.stubGlobal('fetch', mockFetch);

    const connector = loadRestConnector(
      {
        endpoint: 'https://api.example.com/students/{id}',
      },
      pseudonymSecret
    );

    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const result = await connector.lookup('err_id');

    expect(result).toBeNull();
    expect(consoleSpy).toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});
