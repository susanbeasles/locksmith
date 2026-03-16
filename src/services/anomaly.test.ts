import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock dependencies before importing the module under test
vi.mock('../utils/audit.js', () => ({
  logAuditEvent: vi.fn(),
}));

vi.mock('./nonce.js', () => ({
  revokeAllNonces: vi.fn().mockResolvedValue(3),
}));

import { checkAnomaly } from './anomaly.js';
import { revokeAllNonces } from './nonce.js';

describe('anomaly detection', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset module-level state by re-importing would be ideal,
    // but we can work with unique userIds per test instead
  });

  it('returns no anomaly for normal access', async () => {
    const result = await checkAnomaly({
      userId: 'normal-user',
      service: 'github',
      scope: 'repo:read',
      accessMethod: 'proxy',
      deviceId: 'device-1',
      ip: '10.0.0.1',
    });

    expect(result.anomalous).toBe(false);
    expect(result.anomalies).toBeUndefined();
  });

  it('flags unsanctioned access method as high severity', async () => {
    const result = await checkAnomaly({
      userId: 'unsanctioned-user',
      service: 'github',
      scope: 'repo:read',
      accessMethod: 'direct_curl',
      deviceId: 'device-1',
      ip: '10.0.0.1',
    });

    expect(result.anomalous).toBe(true);
    expect(result.severity).toBe('high');
    expect(result.anomalies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: 'unsanctioned_access_method' }),
      ]),
    );
  });

  it('revokes nonces on high severity anomaly', async () => {
    const result = await checkAnomaly({
      userId: 'revoke-user',
      service: 'github',
      scope: 'repo:read',
      accessMethod: 'unknown_method',
    });

    expect(result.action).toBe('nonces_revoked');
    expect(result.revoked).toBe(3);
    expect(revokeAllNonces).toHaveBeenCalledWith('revoke-user');
  });

  it('flags wildcard scope as medium severity', async () => {
    const result = await checkAnomaly({
      userId: 'wildcard-user',
      service: 'github',
      scope: '*',
      accessMethod: 'proxy',
    });

    expect(result.anomalous).toBe(true);
    expect(result.severity).toBe('medium');
    expect(result.anomalies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: 'wildcard_scope' }),
      ]),
    );
    expect(result.action).toBe('alert_only');
  });

  it('flags wildcard in object scope', async () => {
    const result = await checkAnomaly({
      userId: 'wildcard-obj-user',
      service: 'slack',
      scope: { channel: '*', method: 'post' },
      accessMethod: 'mcp_tool',
    });

    expect(result.anomalous).toBe(true);
    expect(result.anomalies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: 'wildcard_scope' }),
      ]),
    );
  });

  it('flags first access to high-value service', async () => {
    const result = await checkAnomaly({
      userId: 'first-access-user',
      service: 'aws-prod',
      scope: 's3:GetObject',
      accessMethod: 'proxy',
    });

    expect(result.anomalous).toBe(true);
    expect(result.anomalies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: 'first_access_high_value' }),
      ]),
    );
  });

  it('detects rapid access pattern', async () => {
    const userId = 'rapid-user';

    // Fire 11 requests (threshold is 10)
    for (let i = 0; i < 11; i++) {
      await checkAnomaly({
        userId,
        service: 'github',
        scope: 'repo:read',
        accessMethod: 'proxy',
        deviceId: 'device-1',
      });
    }

    const result = await checkAnomaly({
      userId,
      service: 'github',
      scope: 'repo:read',
      accessMethod: 'proxy',
      deviceId: 'device-1',
    });

    expect(result.anomalous).toBe(true);
    expect(result.anomalies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ rule: 'rapid_access' }),
      ]),
    );
  });

  it('allows all sanctioned access methods', async () => {
    const methods = ['proxy', 'op_run', 'connect_server', 'mcp_tool'];

    for (const method of methods) {
      const result = await checkAnomaly({
        userId: `sanctioned-${method}`,
        service: 'github',
        scope: 'repo:read',
        accessMethod: method,
      });

      // Should not flag unsanctioned_access_method
      const methodAnomaly = result.anomalies?.find(
        (a) => a.rule === 'unsanctioned_access_method',
      );
      expect(methodAnomaly).toBeUndefined();
    }
  });
});
