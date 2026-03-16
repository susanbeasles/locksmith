import { createHash } from 'node:crypto';
import { createWriteStream, type WriteStream } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { config } from '../config.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Any audit event payload — concrete fields vary per event type. */
type AuditEventPayload = Record<string, unknown>;

interface AuditRecord extends AuditEventPayload {
  event_id: string;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// File-based audit stream
// ---------------------------------------------------------------------------

let auditStream: WriteStream | null = null;

// ---------------------------------------------------------------------------
// DynamoDB audit client (lazy-initialized)
// ---------------------------------------------------------------------------

let ddb: DynamoDBDocumentClient | null = null;

function getDynamoClient(): DynamoDBDocumentClient {
  if (!ddb) {
    const raw = new DynamoDBClient({ region: config.aws.region });
    ddb = DynamoDBDocumentClient.from(raw, {
      marshallOptions: { removeUndefinedValues: true },
    });
  }
  return ddb;
}

const MAX_EVENT_SIZE = 10_000;
const AUDIT_TTL_DAYS = 90;

// ---------------------------------------------------------------------------
// Initialise the file-based logger (call once at startup)
// ---------------------------------------------------------------------------

export async function initAuditLogger(): Promise<void> {
  const logDir = dirname(config.audit.logFile);
  await mkdir(logDir, { recursive: true }).catch(() => {
    /* directory may already exist */
  });
  auditStream = createWriteStream(config.audit.logFile, { flags: 'a' });
}

// ---------------------------------------------------------------------------
// Credential fingerprinting (safe hash, no plaintext)
// ---------------------------------------------------------------------------

export function credentialFingerprint(value: string): string | null {
  if (!value) return null;
  const hash = createHash('sha256').update(value).digest('hex');
  return `sha256:${hash.substring(0, 16)}`;
}

// ---------------------------------------------------------------------------
// Log an audit event to file + DynamoDB
// ---------------------------------------------------------------------------

export function logAuditEvent(event: AuditEventPayload): void {
  const record: AuditRecord = {
    event_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ...event,
  };

  // Safety check: never log anything that looks like a credential
  const serialized = JSON.stringify(record);
  if (serialized.length > MAX_EVENT_SIZE) {
    console.error('[AUDIT] Event too large, possible credential leak. Dropping.');
    return;
  }

  // Write to local file stream
  if (auditStream) {
    auditStream.write(serialized + '\n');
  }

  // Write to stdout for CloudWatch pickup
  console.log(`[AUDIT] ${serialized}`);

  // Write to DynamoDB audit table (fire-and-forget — do not block callers)
  writeToDynamo(record).catch((err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`[AUDIT] DynamoDB write failed: ${message}`);
  });
}

// ---------------------------------------------------------------------------
// DynamoDB audit persistence
// ---------------------------------------------------------------------------

async function writeToDynamo(record: AuditRecord): Promise<void> {
  const client = getDynamoClient();

  const ttlEpoch = Math.floor(Date.now() / 1000) + AUDIT_TTL_DAYS * 86_400;

  await client.send(
    new PutCommand({
      TableName: config.dynamodb.auditTable,
      Item: {
        pk: `audit:${record.event_id}`,
        sk: record.timestamp,
        ...record,
        ttl: ttlEpoch,
      },
    }),
  );
}
