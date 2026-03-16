export const config = {
  port: parseInt(process.env.LOCKSMITH_PORT || '3100'),

  entra: {
    tenantId: process.env.ENTRA_TENANT_ID!,
    clientId: process.env.ENTRA_CLIENT_ID!,
    issuer: `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/v2.0`,
    jwksUri: `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/discovery/v2.0/keys`,
  },

  aws: {
    region: process.env.AWS_REGION || process.env.AWS_REGION_DEPLOY || 'us-east-1',
  },

  dynamodb: {
    noncesTable: process.env.DYNAMODB_TABLE || 'locksmith-nonces-prod',
    auditTable: process.env.AUDIT_TABLE || 'locksmith-audit-prod',
  },

  kms: {
    keyId: process.env.KMS_KEY_ID!,
  },

  nonce: {
    defaultTtlSeconds: 900,
    defaultType: 'session' as const,
    maxActivePerUser: 20,
  },

  audit: {
    logFile: process.env.AUDIT_LOG_PATH || '/var/log/locksmith/audit.jsonl',
  },
} as const;

export type NonceType = 'single_use' | 'session';
