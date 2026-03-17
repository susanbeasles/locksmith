import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Request, Response, NextFunction } from 'express';

const { mockJwtVerify } = vi.hoisted(() => ({
  mockJwtVerify: vi.fn(),
}));

vi.mock('jose', () => ({
  createRemoteJWKSet: vi.fn().mockReturnValue('mock-jwks'),
  jwtVerify: mockJwtVerify,
}));

vi.mock('../config.js', () => ({
  config: {
    entra: {
      tenantId: 'test-tenant',
      clientId: 'test-client',
      issuer: 'https://login.microsoftonline.com/test-tenant/v2.0',
      jwksUri: 'https://login.microsoftonline.com/test-tenant/discovery/v2.0/keys',
    },
  },
}));

vi.mock('../utils/audit.js', () => ({
  logAuditEvent: vi.fn(),
}));

import { requireAuth, requireAuthStrength } from './auth.js';
import { logAuditEvent } from '../utils/audit.js';

function mockReq(overrides: Partial<Request> = {}): Request {
  return {
    headers: {},
    ip: '127.0.0.1',
    identity: undefined as unknown,
    ...overrides,
  } as Request;
}

function mockRes(): Response {
  const res = {
    statusCode: 200,
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };
  return res as unknown as Response;
}

describe('requireAuth', () => {
  const next: NextFunction = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects request with no Authorization header', async () => {
    const req = mockReq();
    const res = mockRes();

    await requireAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('Missing') }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects request with non-Bearer Authorization', async () => {
    const req = mockReq({ headers: { authorization: 'Basic abc123' } });
    const res = mockRes();

    await requireAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('attaches identity and calls next on valid token', async () => {
    mockJwtVerify.mockResolvedValueOnce({
      payload: {
        sub: 'user-sub',
        oid: 'user-oid',
        name: 'Test User',
        preferred_username: 'test@sonarmd.com',
        groups: ['group-1'],
        deviceid: 'device-abc',
        acrs: 'c1',
        tid: 'test-tenant',
      },
    });

    const req = mockReq({ headers: { authorization: 'Bearer valid-token' } });
    const res = mockRes();

    await requireAuth(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.identity).toEqual({
      sub: 'user-sub',
      oid: 'user-oid',
      name: 'Test User',
      email: 'test@sonarmd.com',
      groups: ['group-1'],
      deviceId: 'device-abc',
      authStrength: 'c1',
      tid: 'test-tenant',
    });
  });

  it('falls back to email when preferred_username is missing', async () => {
    mockJwtVerify.mockResolvedValueOnce({
      payload: {
        sub: 'user-sub',
        email: 'fallback@sonarmd.com',
      },
    });

    const req = mockReq({ headers: { authorization: 'Bearer valid-token' } });
    const res = mockRes();

    await requireAuth(req, res, next);

    expect(req.identity.email).toBe('fallback@sonarmd.com');
  });

  it('returns 401 and logs audit event on invalid token', async () => {
    mockJwtVerify.mockRejectedValueOnce(new Error('Token expired'));

    const req = mockReq({ headers: { authorization: 'Bearer expired-token' } });
    const res = mockRes();

    await requireAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('Invalid') }),
    );
    expect(logAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({ event_type: 'auth_failure' }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('handles missing optional claims gracefully', async () => {
    mockJwtVerify.mockResolvedValueOnce({
      payload: { sub: 'minimal-user' },
    });

    const req = mockReq({ headers: { authorization: 'Bearer minimal-token' } });
    const res = mockRes();

    await requireAuth(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.identity).toEqual({
      sub: 'minimal-user',
      oid: '',
      name: '',
      email: '',
      groups: [],
      deviceId: null,
      authStrength: null,
      tid: '',
    });
  });
});

describe('requireAuthStrength', () => {
  const next: NextFunction = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('passes when auth strength matches fido2 (c1)', () => {
    const middleware = requireAuthStrength('fido2');
    const req = mockReq();
    req.identity = {
      sub: 'u', oid: 'o', name: 'n', email: 'e',
      groups: [], deviceId: null, authStrength: 'c1', tid: 't',
    };
    const res = mockRes();

    middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('rejects when auth strength is insufficient', () => {
    const middleware = requireAuthStrength('fido2');
    const req = mockReq();
    req.identity = {
      sub: 'u', oid: 'o', name: 'n', email: 'e',
      groups: [], deviceId: null, authStrength: null, tid: 't',
    };
    const res = mockRes();

    middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ error: expect.stringContaining('Phishing-resistant') }),
    );
    expect(next).not.toHaveBeenCalled();
  });

  it('logs audit event on insufficient strength', () => {
    const middleware = requireAuthStrength('fido2');
    const req = mockReq();
    req.identity = {
      sub: 'u', oid: 'user-oid', name: 'n', email: 'e',
      groups: [], deviceId: null, authStrength: 'c2', tid: 't',
    };
    const res = mockRes();

    middleware(req, res, next);

    expect(logAuditEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        event_type: 'auth_strength_insufficient',
        user: 'user-oid',
      }),
    );
  });
});
