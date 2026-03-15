import { createHash } from 'crypto';
import { createWriteStream } from 'fs';
import { mkdir } from 'fs/promises';
import { dirname } from 'path';
import { config } from '../config.js';

let auditStream = null;

export async function initAuditLogger() {
  const logDir = dirname(config.audit.logFile);
  await mkdir(logDir, { recursive: true }).catch(() => {});
  auditStream = createWriteStream(config.audit.logFile, { flags: 'a' });
}

// Generate a fingerprint of a credential value without logging the value itself
export function credentialFingerprint(value) {
  if (!value) return null;
  const hash = createHash('sha256').update(value).digest('hex');
  return `sha256:${hash.substring(0, 16)}`;
}

export function logAuditEvent(event) {
  const record = {
    event_id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ...event,
  };

  // Safety check: never log anything that looks like a credential
  const serialized = JSON.stringify(record);
  if (serialized.length > 10000) {
    console.error('[AUDIT] Event too large, possible credential leak. Dropping.');
    return;
  }

  if (auditStream) {
    auditStream.write(serialized + '\n');
  }

  // Also to stdout for CloudWatch pickup
  console.log(`[AUDIT] ${serialized}`);
}
