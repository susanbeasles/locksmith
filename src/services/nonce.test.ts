import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockSend } = vi.hoisted(() => ({
  mockSend: vi.fn(),
}));

vi.mock('@aws-sdk/client-dynamodb', () => {
  class MockDynamoDBClient {
    constructor() { /* noop */ }
  }
  return { DynamoDBClient: MockDynamoDBClient };
});

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: vi.fn().mockReturnValue({ send: mockSend }),
  },
  PutCommand: class PutCommand { constructor(public input: unknown) {} },
  GetCommand: class GetCommand { constructor(public input: unknown) {} },
  DeleteCommand: class DeleteCommand { constructor(public input: unknown) {} },
  QueryCommand: class QueryCommand { constructor(public input: unknown) {} },
  UpdateCommand: class UpdateCommand { constructor(public input: unknown) {} },
}));

vi.mock('../utils/audit.js', () => ({
  logAuditEvent: vi.fn(),
}));

vi.mock('../config.js', () => ({
  config: {
    aws: { region: 'us-east-1' },
    dynamodb: { noncesTable: 'test-nonces' },
    nonce: {
      defaultTtlSeconds: 900,
      defaultType: 'session',
      maxActivePerUser: 20,
    },
  },
}));

import { issueNonce, validateNonce, revokeAllNonces, getNoncePolicy } from './nonce.js';

describe('nonce service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('getNoncePolicy', () => {
    it('returns configured policy for known services', () => {
      const policy = getNoncePolicy('aws-prod');
      expect(policy.type).toBe('single_use');
      expect(policy.ttl).toBe(900);
    });

    it('returns default policy for unknown services', () => {
      const policy = getNoncePolicy('unknown-service');
      expect(policy.type).toBe('session');
      expect(policy.ttl).toBe(900);
    });

    it('github has session nonces with 1hr TTL', () => {
      const policy = getNoncePolicy('github');
      expect(policy.type).toBe('session');
      expect(policy.ttl).toBe(3600);
    });

    it('circleci has single-use nonces with short TTL', () => {
      const policy = getNoncePolicy('circleci');
      expect(policy.type).toBe('single_use');
      expect(policy.ttl).toBe(300);
    });
  });

  describe('issueNonce', () => {
    it('issues a nonce and returns expected structure', async () => {
      mockSend.mockResolvedValueOnce({ Count: 0 });
      mockSend.mockResolvedValueOnce({});

      const result = await issueNonce({
        userId: 'user-1',
        service: 'github',
        scope: 'repo:read',
        deviceId: 'device-1',
      });

      expect(result.nonce).toBeDefined();
      expect(result.type).toBe('session');
      expect(result.ttl).toBe(3600);
      expect(result.expiresAt).toBeDefined();
      expect(result.proxyBase).toBe('/proxy/github');
    });

    it('rejects when max active nonces reached', async () => {
      mockSend.mockResolvedValueOnce({ Count: 20 });

      await expect(
        issueNonce({
          userId: 'busy-user',
          service: 'github',
          scope: 'repo:read',
        }),
      ).rejects.toThrow('Max active nonces');
    });
  });

  describe('validateNonce', () => {
    const makeNonce = (overrides = {}) => ({
      pk: 'nonce:user-1',
      sk: 'nonce-123',
      id: 'nonce-123',
      userId: 'user-1',
      service: 'github',
      scope: 'repo:read',
      deviceId: null,
      type: 'session',
      createdAt: Date.now(),
      consumed: false,
      useCount: 0,
      ttl: Math.floor(Date.now() / 1000) + 3600,
      ...overrides,
    });

    it('validates a valid session nonce', async () => {
      mockSend.mockResolvedValueOnce({ Item: makeNonce() });
      mockSend.mockResolvedValueOnce({});

      const result = await validateNonce('nonce-123', 'user-1', 'github', 'repo:read');

      expect(result.valid).toBe(true);
      expect(result.nonce).toBeDefined();
    });

    it('rejects nonce not found', async () => {
      mockSend.mockResolvedValueOnce({ Item: undefined });

      const result = await validateNonce('missing', 'user-1', 'github', 'repo:read');

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('not found');
    });

    it('rejects nonce belonging to different user', async () => {
      mockSend.mockResolvedValueOnce({ Item: makeNonce({ userId: 'other-user' }) });

      const result = await validateNonce('nonce-123', 'user-1', 'github', 'repo:read');

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('does not belong');
    });

    it('rejects nonce for wrong service', async () => {
      mockSend.mockResolvedValueOnce({ Item: makeNonce({ service: 'slack' }) });

      const result = await validateNonce('nonce-123', 'user-1', 'github', 'repo:read');

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('slack');
    });

    it('rejects consumed single-use nonce', async () => {
      mockSend.mockResolvedValueOnce({
        Item: makeNonce({ type: 'single_use', consumed: true }),
      });

      const result = await validateNonce('nonce-123', 'user-1', 'github', 'repo:read');

      expect(result.valid).toBe(false);
      expect(result.reason).toContain('already consumed');
    });

    it('deletes single-use nonce on consumption', async () => {
      mockSend.mockResolvedValueOnce({
        Item: makeNonce({ type: 'single_use' }),
      });
      mockSend.mockResolvedValueOnce({});

      const result = await validateNonce('nonce-123', 'user-1', 'github', 'repo:read');

      expect(result.valid).toBe(true);
      expect(mockSend).toHaveBeenCalledTimes(2);
    });
  });

  describe('revokeAllNonces', () => {
    it('revokes all nonces for a user', async () => {
      mockSend.mockResolvedValueOnce({
        Items: [{ sk: 'nonce-1' }, { sk: 'nonce-2' }, { sk: 'nonce-3' }],
      });
      mockSend.mockResolvedValue({});

      const count = await revokeAllNonces('user-1');

      expect(count).toBe(3);
      expect(mockSend).toHaveBeenCalledTimes(4);
    });

    it('returns 0 when user has no nonces', async () => {
      mockSend.mockResolvedValueOnce({ Items: [] });

      const count = await revokeAllNonces('empty-user');

      expect(count).toBe(0);
    });
  });
});
