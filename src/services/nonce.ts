import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  DeleteCommand,
  QueryCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { v4 as uuidv4 } from 'uuid';
import { config, type NonceType } from '../config.js';
import { logAuditEvent } from '../utils/audit.js';

// ---------------------------------------------------------------------------
// DynamoDB client (module-level singleton)
// ---------------------------------------------------------------------------

const ddbClient = new DynamoDBClient({ region: config.aws.region });
const ddb = DynamoDBDocumentClient.from(ddbClient, {
  marshallOptions: { removeUndefinedValues: true },
});

const TABLE = config.dynamodb.noncesTable;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface NoncePolicy {
  type: NonceType;
  ttl: number;
  maxScope: string;
}

interface NonceData {
  pk: string;       // nonce:{userId}
  sk: string;       // {nonceId}
  id: string;
  userId: string;
  service: string;
  scope: string | Record<string, string>;
  deviceId: string | null;
  type: NonceType;
  createdAt: number;
  consumed: boolean;
  useCount: number;
  ttl: number;      // Unix epoch seconds — DynamoDB TTL
}

interface IssueNonceParams {
  userId: string;
  service: string;
  scope: string | Record<string, string>;
  deviceId?: string;
}

interface NonceResult {
  nonce: string;
  type: NonceType;
  ttl: number;
  expiresAt: string;
  proxyBase: string;
}

interface ValidationResult {
  valid: boolean;
  reason?: string;
  nonce?: NonceData;
}

// ---------------------------------------------------------------------------
// Service-specific nonce policies
// ---------------------------------------------------------------------------

const NONCE_POLICIES: Record<string, NoncePolicy> = {
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

export function getNoncePolicy(service: string): NoncePolicy {
  return NONCE_POLICIES[service] ?? {
    type: config.nonce.defaultType,
    ttl: config.nonce.defaultTtlSeconds,
    maxScope: 'action',
  };
}

// ---------------------------------------------------------------------------
// Issue a new nonce
// ---------------------------------------------------------------------------

export async function issueNonce({
  userId,
  service,
  scope,
  deviceId,
}: IssueNonceParams): Promise<NonceResult> {
  const policy = getNoncePolicy(service);
  const nonceId = uuidv4();

  // Check active nonce count for this user via query on pk
  const existing = await ddb.send(
    new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': `nonce:${userId}` },
      Select: 'COUNT',
    }),
  );

  const activeCount = existing.Count ?? 0;
  if (activeCount >= config.nonce.maxActivePerUser) {
    throw new Error(
      `Max active nonces (${config.nonce.maxActivePerUser}) reached. Revoke existing nonces or wait for expiry.`,
    );
  }

  const nowMs = Date.now();
  const ttlEpoch = Math.floor(nowMs / 1000) + policy.ttl;

  const item: NonceData = {
    pk: `nonce:${userId}`,
    sk: nonceId,
    id: nonceId,
    userId,
    service,
    scope,
    deviceId: deviceId ?? null,
    type: policy.type,
    createdAt: nowMs,
    consumed: false,
    useCount: 0,
    ttl: ttlEpoch,
  };

  await ddb.send(new PutCommand({ TableName: TABLE, Item: item }));

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
    expiresAt: new Date(nowMs + policy.ttl * 1000).toISOString(),
    proxyBase: `/proxy/${service}`,
  };
}

// ---------------------------------------------------------------------------
// Validate and optionally consume a nonce
// ---------------------------------------------------------------------------

export async function validateNonce(
  nonceId: string,
  userId: string,
  service: string,
  requestedAction: string | Record<string, string>,
): Promise<ValidationResult> {
  const result = await ddb.send(
    new GetCommand({
      TableName: TABLE,
      Key: { pk: `nonce:${userId}`, sk: nonceId },
    }),
  );

  const nonce = result.Item as NonceData | undefined;

  if (!nonce) {
    return { valid: false, reason: 'Nonce not found or expired' };
  }

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
    await ddb.send(
      new DeleteCommand({ TableName: TABLE, Key: { pk: `nonce:${userId}`, sk: nonceId } }),
    );
  } else {
    // Update use count for session nonces
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE,
        Key: { pk: `nonce:${userId}`, sk: nonceId },
        UpdateExpression: 'SET useCount = useCount + :inc, consumed = :t',
        ExpressionAttributeValues: { ':inc': 1, ':t': true },
      }),
    );
    nonce.useCount += 1;
    nonce.consumed = true;
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

// ---------------------------------------------------------------------------
// Revoke all nonces for a user (used by anomaly detection)
// ---------------------------------------------------------------------------

export async function revokeAllNonces(userId: string): Promise<number> {
  const pk = `nonce:${userId}`;

  // Query all sort keys for this user
  const result = await ddb.send(
    new QueryCommand({
      TableName: TABLE,
      KeyConditionExpression: 'pk = :pk',
      ExpressionAttributeValues: { ':pk': pk },
      ProjectionExpression: 'sk',
    }),
  );

  const items = result.Items ?? [];

  // Delete each nonce (DynamoDB BatchWrite is limited to 25; use individual deletes
  // since revocation is infrequent and correctness matters more than throughput)
  await Promise.all(
    items.map((item) =>
      ddb.send(new DeleteCommand({ TableName: TABLE, Key: { pk, sk: item.sk as string } })),
    ),
  );

  logAuditEvent({
    event_type: 'nonces_revoked_all',
    user: userId,
    count: items.length,
  });

  return items.length;
}

// ---------------------------------------------------------------------------
// Scope matching
// ---------------------------------------------------------------------------

function scopeMatches(
  declaredScope: string | Record<string, string>,
  requestedAction: string | Record<string, string>,
): boolean {
  if (!declaredScope || !requestedAction) return false;

  const declared =
    typeof declaredScope === 'string' ? declaredScope : JSON.stringify(declaredScope);
  const requested =
    typeof requestedAction === 'string' ? requestedAction : JSON.stringify(requestedAction);

  // Wildcard scope
  if (declared === '*') return true;

  // Exact match
  if (declared === requested) return true;

  // Prefix match (e.g., scope "s3:Get" matches action "s3:GetObject")
  if (requested.startsWith(declared)) return true;

  // Object scope matching
  if (typeof declaredScope === 'object' && typeof requestedAction === 'object') {
    return Object.entries(declaredScope).every(
      ([key, value]) => requestedAction[key] === value || value === '*',
    );
  }

  return false;
}
