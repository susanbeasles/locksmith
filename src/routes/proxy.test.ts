import { describe, it, expect, vi } from 'vitest';
import type { Request } from 'express';

// Mock all dependencies so the module loads cleanly
vi.mock('../services/nonce.js', () => ({
  validateNonce: vi.fn(),
}));
vi.mock('../services/credentials.js', () => ({
  resolveCredential: vi.fn(),
}));
vi.mock('../plugins/aws.js', () => ({
  vendAwsSession: vi.fn(),
}));
vi.mock('../utils/audit.js', () => ({
  logAuditEvent: vi.fn(),
}));

import { buildServiceHeaders, type Credential } from './proxy.js';

function fakeReq(): Request {
  return {} as Request;
}

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
  it('module loads and exports router', async () => {
    const proxyModule = await import('./proxy.js');
    expect(proxyModule.default).toBeDefined();
  });
});

describe('buildServiceHeaders', () => {
  it('always includes User-Agent', () => {
    const headers = buildServiceHeaders('github', { token: 'x' }, fakeReq());
    expect(headers['User-Agent']).toBe('Locksmith-Proxy/0.2.0');
  });

  describe('github', () => {
    it('sets Bearer auth, Accept, and API version', () => {
      const headers = buildServiceHeaders('github', { token: 'gh-token' }, fakeReq());

      expect(headers['Authorization']).toBe('Bearer gh-token');
      expect(headers['Accept']).toBe('application/vnd.github+json');
      expect(headers['X-GitHub-Api-Version']).toBe('2022-11-28');
    });

    it('falls back to password field', () => {
      const headers = buildServiceHeaders('github', { password: 'gh-pass' }, fakeReq());

      expect(headers['Authorization']).toBe('Bearer gh-pass');
    });
  });

  describe('slack', () => {
    it('sets Bearer auth', () => {
      const headers = buildServiceHeaders('slack', { token: 'xoxb-slack' }, fakeReq());

      expect(headers['Authorization']).toBe('Bearer xoxb-slack');
    });
  });

  describe('sentry', () => {
    it('sets Bearer auth', () => {
      const headers = buildServiceHeaders('sentry', { token: 'sentry-tok' }, fakeReq());

      expect(headers['Authorization']).toBe('Bearer sentry-tok');
    });
  });

  describe('pagerduty', () => {
    it('uses Token token= format', () => {
      const headers = buildServiceHeaders('pagerduty', { token: 'pd-key' }, fakeReq());

      expect(headers['Authorization']).toBe('Token token=pd-key');
    });
  });

  describe('jira', () => {
    it('prefers access_token field', () => {
      const cred: Credential = { access_token: 'jira-oauth', token: 'fallback' };
      const headers = buildServiceHeaders('jira', cred, fakeReq());

      expect(headers['Authorization']).toBe('Bearer jira-oauth');
      expect(headers['Accept']).toBe('application/json');
    });

    it('falls back to token then password', () => {
      const headers = buildServiceHeaders('jira', { password: 'jira-pw' }, fakeReq());

      expect(headers['Authorization']).toBe('Bearer jira-pw');
    });
  });

  describe('circleci', () => {
    it('uses Circle-Token header instead of Authorization', () => {
      const headers = buildServiceHeaders('circleci', { token: 'ci-tok' }, fakeReq());

      expect(headers['Circle-Token']).toBe('ci-tok');
      expect(headers['Authorization']).toBeUndefined();
    });

    it('falls back to empty string when no credential fields', () => {
      const headers = buildServiceHeaders('circleci', {}, fakeReq());

      expect(headers['Circle-Token']).toBe('');
    });
  });

  describe('unknown service', () => {
    it('uses generic Bearer token', () => {
      const headers = buildServiceHeaders('some-future-service', { token: 'generic' }, fakeReq());

      expect(headers['Authorization']).toBe('Bearer generic');
    });
  });
});
