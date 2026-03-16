import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from '@aws-sdk/client-secrets-manager';
import {
  KMSClient,
  EncryptCommand,
  DecryptCommand,
} from '@aws-sdk/client-kms';
import { config } from '../config.js';

// ---------------------------------------------------------------------------
// AWS clients (module-level singletons)
// ---------------------------------------------------------------------------

const smClient = new SecretsManagerClient({ region: config.aws.region });
const kmsClient = new KMSClient({ region: config.aws.region });

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CredentialSource {
  secretId: string;
}

interface CachedCredential {
  value: CredentialPayload;
  expiresAt: number;
}

/** Credential payload returned by Secrets Manager — always a key/value map. */
type CredentialPayload = Record<string, string>;

interface EnvelopeEncrypted {
  ciphertextBlob: Uint8Array;
  keyId: string;
}

// ---------------------------------------------------------------------------
// Credential source registry — all credentials live in Secrets Manager now
// ---------------------------------------------------------------------------

const CREDENTIAL_SOURCES: Record<string, CredentialSource> = {
  'aws-prod':      { secretId: 'locksmith/aws/prod' },
  'aws-dev':       { secretId: 'locksmith/aws/dev' },
  'github':        { secretId: 'locksmith/github/app-key' },
  'slack':         { secretId: 'locksmith/slack/bot-token' },
  'mongodb-atlas': { secretId: 'locksmith/mongodb/atlas' },
  'postgres':      { secretId: 'locksmith/postgres/prod' },
  'sentry':        { secretId: 'locksmith/sentry/api-token' },
  'pagerduty':     { secretId: 'locksmith/pagerduty/api-key' },
  'jira':          { secretId: 'locksmith/jira/oauth-token' },
  'circleci':      { secretId: 'locksmith/circleci/api-token' },
  'ssh-ca':        { secretId: 'locksmith/ssh/ca' },
};

// ---------------------------------------------------------------------------
// In-memory credential cache with TTL
// ---------------------------------------------------------------------------

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const credentialCache = new Map<string, CachedCredential>();

function getCached(service: string): CredentialPayload | undefined {
  const entry = credentialCache.get(service);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    credentialCache.delete(service);
    return undefined;
  }
  return entry.value;
}

function setCache(service: string, value: CredentialPayload): void {
  credentialCache.set(service, {
    value,
    expiresAt: Date.now() + CACHE_TTL_MS,
  });
}

/** Flush the entire cache (useful on key rotation or anomaly revocation). */
export function invalidateCache(service?: string): void {
  if (service) {
    credentialCache.delete(service);
  } else {
    credentialCache.clear();
  }
}

// ---------------------------------------------------------------------------
// Resolve a real credential for a service
// This is the ONLY function in the entire system that touches plaintext creds.
// The returned value must NEVER be logged, stored to disk, or returned to a
// client.
// ---------------------------------------------------------------------------

export async function resolveCredential(
  service: string,
): Promise<CredentialPayload> {
  const source = CREDENTIAL_SOURCES[service];
  if (!source) {
    throw new Error(`No credential source configured for service: ${service}`);
  }

  // Check cache first
  const cached = getCached(service);
  if (cached) return cached;

  const credential = await resolveFromSecretsManager(source.secretId);
  setCache(service, credential);
  return credential;
}

// ---------------------------------------------------------------------------
// Secrets Manager retrieval
// ---------------------------------------------------------------------------

async function resolveFromSecretsManager(
  secretId: string,
): Promise<CredentialPayload> {
  const response = await smClient.send(
    new GetSecretValueCommand({ SecretId: secretId }),
  );

  if (response.SecretString) {
    try {
      return JSON.parse(response.SecretString) as CredentialPayload;
    } catch {
      return { value: response.SecretString };
    }
  }

  throw new Error(`Secret ${secretId} has no string value`);
}

// ---------------------------------------------------------------------------
// KMS envelope encryption helpers
// ---------------------------------------------------------------------------

/**
 * Encrypt arbitrary plaintext using the locksmith KMS key.
 * Returns the ciphertext blob and key ID so the caller can store them.
 * The plaintext is never written to disk or logged.
 */
export async function envelopeEncrypt(
  plaintext: string,
): Promise<EnvelopeEncrypted> {
  const response = await kmsClient.send(
    new EncryptCommand({
      KeyId: config.kms.keyId,
      Plaintext: new TextEncoder().encode(plaintext),
    }),
  );

  if (!response.CiphertextBlob) {
    throw new Error('KMS Encrypt returned no ciphertext');
  }

  return {
    ciphertextBlob: response.CiphertextBlob,
    keyId: config.kms.keyId,
  };
}

/**
 * Decrypt a ciphertext blob previously encrypted with `envelopeEncrypt`.
 * Returns the plaintext string. Caller is responsible for memory hygiene.
 */
export async function envelopeDecrypt(
  ciphertextBlob: Uint8Array,
): Promise<string> {
  const response = await kmsClient.send(
    new DecryptCommand({ CiphertextBlob: ciphertextBlob }),
  );

  if (!response.Plaintext) {
    throw new Error('KMS Decrypt returned no plaintext');
  }

  return new TextDecoder().decode(response.Plaintext);
}
