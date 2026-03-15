// Locksmith configuration
// All values come from environment variables injected via op run
// No secrets in this file. Ever.

export const config = {
  port: parseInt(process.env.LOCKSMITH_PORT || '3100'),
  
  // Entra ID OIDC
  entra: {
    tenantId: process.env.ENTRA_TENANT_ID,
    clientId: process.env.ENTRA_CLIENT_ID, // Locksmith's app registration client ID
    issuer: `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/v2.0`,
    jwksUri: `https://login.microsoftonline.com/${process.env.ENTRA_TENANT_ID}/discovery/v2.0/keys`,
  },

  // Redis (nonce state)
  redis: {
    host: process.env.REDIS_HOST || '127.0.0.1',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    tls: process.env.REDIS_TLS === 'true',
  },

  // Nonce defaults (overridable per service in policy)
  nonce: {
    defaultTtlSeconds: 900,       // 15 minutes
    defaultType: 'session',       // 'single_use' or 'session'
    maxActivePerUser: 20,
  },

  // Audit
  audit: {
    logFile: process.env.AUDIT_LOG_PATH || '/var/log/locksmith/audit.jsonl',
    cloudwatch: process.env.CLOUDWATCH_LOG_GROUP || null,
  },

  // AWS region
  aws: {
    region: process.env.AWS_REGION || 'us-east-1',
  },
};
