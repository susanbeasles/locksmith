import Redis from 'ioredis';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config.js';
import { logAuditEvent } from '../utils/audit.js';

let redis = null;

export function initRedis() {
  redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    tls: config.redis.tls ? {} : undefined,
    maxRetriesPerRequest: 3,
    retryStrategy: (times) => Math.min(times * 100, 3000),
  });

  redis.on('error', (err) => {
    console.error('[REDIS] Connection error:', err.message);
  });

  redis.on('connect', () => {
    console.log('[REDIS] Connected');
  });

  return redis;
}

// Service-specific nonce policies
const NONCE_POLICIES = {
  'aws-prod':      { type: 'single_use', ttl: 900,  maxScope: 'action+resource' },
  'aws-dev':       { type: 'session',    ttl: 3600, maxScope: 'action_prefix' },
  'github':        { type: 'session',    ttl: 3600, maxScope: 'repo+permission' },
  'slack':         { type: 'session',    ttl: 1800, maxScope: 'channel+method' },
  'mongodb-atlas': { type: 'single_use', ttl: 300,  maxScope: 'database+operation' },
  'postgres':      { type: 'session',    ttl: 1800, maxScope: 'database+role' },
  'sentry':        { type: 'session',    ttl: 3600, maxScope: 'project+endpoint' },
  'pagerduty':     { type: 'session',    ttl: 3600, maxScope: 'service+method' },
  'jira':          { type: 'session',    ttl: 3600, maxScope: 'project+method' },
  'circleci':      { type: 'single_use', ttl: 300,  maxScope: 'pipeline+action' },
};

export function getNoncePolicy(service) {
  return NONCE_POLICIES[service] || {
    type: config.nonce.defaultType,
    ttl: config.nonce.defaultTtlSeconds,
    maxScope: 'action',
  };
}

// Issue a new nonce
export async function issueNonce({ userId, service, scope, deviceId }) {
  const policy = getNoncePolicy(service);
  const nonceId = uuidv4();

  const nonceData = {
    id: nonceId,
    userId,
    service,
    scope,
    deviceId: deviceId || null,
    type: policy.type,
    createdAt: Date.now(),
    consumed: false,
    useCount: 0,
  };

  // Check active nonce count for this user
  const activeKeys = await redis.keys(`nonce:${userId}:*`);
  if (activeKeys.length >= config.nonce.maxActivePerUser) {
    throw new Error(`Max active nonces (${config.nonce.maxActivePerUser}) reached. Revoke existing nonces or wait for expiry.`);
  }

  const key = `nonce:${userId}:${nonceId}`;
  await redis.set(key, JSON.stringify(nonceData), 'EX', policy.ttl);

  logAuditEvent({
    event_type: 'nonce_issued',
    user: userId,
    nonce_id: nonceId,
    service,
    scope,
    nonce_type: policy.type,
    nonce_ttl_seconds: policy.ttl,
    device_id: deviceId,
  });

  return {
    nonce: nonceId,
    type: policy.type,
    ttl: policy.ttl,
    expiresAt: new Date(Date.now() + policy.ttl * 1000).toISOString(),
    proxyBase: `/proxy/${service}`,
  };
}

// Validate and optionally consume a nonce
export async function validateNonce(nonceId, userId, service, requestedAction) {
  // Try to find the nonce - we key by userId so we need to look it up
  const key = `nonce:${userId}:${nonceId}`;
  const raw = await redis.get(key);

  if (!raw) {
    return { valid: false, reason: 'Nonce not found or expired' };
  }

  const nonce = JSON.parse(raw);

  // Validate ownership
  if (nonce.userId !== userId) {
    logAuditEvent({
      event_type: 'nonce_hijack_attempt',
      nonce_id: nonceId,
      claimed_user: userId,
      actual_user: nonce.userId,
      service,
    });
    return { valid: false, reason: 'Nonce does not belong to this user' };
  }

  // Validate service match
  if (nonce.service !== service) {
    return { valid: false, reason: `Nonce issued for ${nonce.service}, used against ${service}` };
  }

  // Validate scope match
  if (!scopeMatches(nonce.scope, requestedAction)) {
    logAuditEvent({
      event_type: 'scope_mismatch',
      nonce_id: nonceId,
      user: userId,
      declared_scope: nonce.scope,
      requested_action: requestedAction,
      service,
    });
    return { valid: false, reason: 'Request does not match declared scope' };
  }

  // Check if single-use and already consumed
  if (nonce.type === 'single_use' && nonce.consumed) {
    return { valid: false, reason: 'Single-use nonce already consumed' };
  }

  // Consume the nonce
  if (nonce.type === 'single_use') {
    // Delete immediately for single-use
    await redis.del(key);
  } else {
    // Update use count for session nonces
    nonce.useCount += 1;
    nonce.consumed = true;
    const ttl = await redis.ttl(key);
    if (ttl > 0) {
      await redis.set(key, JSON.stringify(nonce), 'EX', ttl);
    }
  }

  logAuditEvent({
    event_type: 'nonce_consumed',
    nonce_id: nonceId,
    user: userId,
    service,
    action: requestedAction,
    nonce_type: nonce.type,
    use_count: nonce.useCount + 1,
  });

  return { valid: true, nonce };
}

// Revoke all nonces for a user (used by anomaly detection)
export async function revokeAllNonces(userId) {
  const keys = await redis.keys(`nonce:${userId}:*`);
  if (keys.length > 0) {
    await redis.del(...keys);
  }

  logAuditEvent({
    event_type: 'nonces_revoked_all',
    user: userId,
    count: keys.length,
  });

  return keys.length;
}

// Scope matching - checks if the requested action falls within the declared scope
function scopeMatches(declaredScope, requestedAction) {
  if (!declaredScope || !requestedAction) return false;

  // Simple prefix matching for now
  // In production, this should be service-specific scope validation
  const declared = typeof declaredScope === 'string' ? declaredScope : JSON.stringify(declaredScope);
  const requested = typeof requestedAction === 'string' ? requestedAction : JSON.stringify(requestedAction);

  // Wildcard scope (should be flagged by anomaly detection but technically valid)
  if (declared === '*') return true;

  // Exact match
  if (declared === requested) return true;

  // Prefix match (e.g., scope "s3:Get" matches action "s3:GetObject")
  if (requested.startsWith(declared)) return true;

  // Object scope matching
  if (typeof declaredScope === 'object' && typeof requestedAction === 'object') {
    return Object.entries(declaredScope).every(
      ([key, value]) => requestedAction[key] === value || value === '*'
    );
  }

  return false;
}
