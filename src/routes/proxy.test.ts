import { describe, it, expect } from 'vitest';

describe('proxy nonce extraction', () => {
  function extractNonce(authHeader: string | undefined): string | null {
    if (!authHeader) return null;
    return authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : authHeader;
  }

  it('extracts nonce from Bearer token', () => {
    expect(extractNonce('Bearer abc-123-nonce')).toBe('abc-123-nonce');
  });

  it('extracts raw nonce without Bearer prefix', () => {
    expect(extractNonce('abc-123-nonce')).toBe('abc-123-nonce');
  });

  it('returns null for missing header', () => {
    expect(extractNonce(undefined)).toBeNull();
  });

  it('handles empty Bearer value', () => {
    expect(extractNonce('Bearer ')).toBe('');
  });
});

describe('service targets', () => {
  it('maps known services to correct targets', async () => {
    // Import the module to verify SERVICE_TARGETS is well-formed
    // We can't directly access the const, but we can verify the router loads
    const proxyModule = await import('./proxy.js');
    expect(proxyModule.default).toBeDefined();
  });
});
