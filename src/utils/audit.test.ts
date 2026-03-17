import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockDdbSend } = vi.hoisted(() => ({
  mockDdbSend: vi.fn(),
}));

vi.mock('@aws-sdk/client-dynamodb', () => ({
  DynamoDBClient: class { constructor() {} },
}));

vi.mock('@aws-sdk/lib-dynamodb', () => ({
  DynamoDBDocumentClient: {
    from: vi.fn().mockReturnValue({ send: mockDdbSend }),
  },
  PutCommand: class { constructor(public input: unknown) {} },
}));

vi.mock('../config.js', () => ({
  config: {
    aws: { region: 'us-east-1' },
    dynamodb: { auditTable: 'test-audit' },
    audit: { logFile: '/tmp/test-audit.jsonl' },
  },
}));

import { credentialFingerprint, logAuditEvent } from './audit.js';

describe('credentialFingerprint', () => {
  it('returns sha256 prefix for a value', () => {
    const fp = credentialFingerprint('test-credential');

    expect(fp).toMatch(/^sha256:[a-f0-9]{16}$/);
  });

  it('returns consistent hash for same input', () => {
    const fp1 = credentialFingerprint('same-value');
    const fp2 = credentialFingerprint('same-value');

    expect(fp1).toBe(fp2);
  });

  it('returns different hashes for different inputs', () => {
    const fp1 = credentialFingerprint('value-a');
    const fp2 = credentialFingerprint('value-b');

    expect(fp1).not.toBe(fp2);
  });

  it('returns null for empty string', () => {
    expect(credentialFingerprint('')).toBeNull();
  });
});

describe('logAuditEvent', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockDdbSend.mockResolvedValue({});
  });

  it('writes event with timestamp and event_id', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    logAuditEvent({ event_type: 'test_event', user: 'test-user' });

    expect(consoleSpy).toHaveBeenCalledTimes(1);
    const logLine = consoleSpy.mock.calls[0][0] as string;
    expect(logLine).toContain('[AUDIT]');
    expect(logLine).toContain('"event_type":"test_event"');
    expect(logLine).toContain('"event_id"');
    expect(logLine).toContain('"timestamp"');

    consoleSpy.mockRestore();
  });

  it('fires DynamoDB write (fire-and-forget)', () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});

    logAuditEvent({ event_type: 'dynamo_test' });

    expect(mockDdbSend).toHaveBeenCalledTimes(1);

    vi.restoreAllMocks();
  });

  it('drops events exceeding max size', () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // Create a payload that exceeds 10KB
    const bigPayload = { event_type: 'big', data: 'x'.repeat(15_000) };
    logAuditEvent(bigPayload);

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Event too large'),
    );
    // Should not write to DynamoDB
    expect(mockDdbSend).not.toHaveBeenCalled();

    consoleSpy.mockRestore();
    errorSpy.mockRestore();
  });
});
