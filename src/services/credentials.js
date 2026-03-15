import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { config } from '../config.js';

const smClient = new SecretsManagerClient({ region: config.aws.region });

// Maps service names to their credential source and retrieval method
const CREDENTIAL_SOURCES = {
  'aws-prod':      { backend: 'secrets-manager', secretId: 'locksmith/aws/prod' },
  'aws-dev':       { backend: 'secrets-manager', secretId: 'locksmith/aws/dev' },
  'github':        { backend: '1password',       vault: 'smd_agora_shared', item: 'github-app-key' },
  'slack':         { backend: '1password',       vault: 'smd_agora_shared', item: 'slack-bot-token' },
  'mongodb-atlas': { backend: 'secrets-manager', secretId: 'locksmith/mongodb/atlas' },
  'postgres':      { backend: 'secrets-manager', secretId: 'locksmith/postgres/prod' },
  'sentry':        { backend: '1password',       vault: 'smd_agora_shared', item: 'sentry-api-token' },
  'pagerduty':     { backend: '1password',       vault: 'smd_agora_shared', item: 'pagerduty-api-key' },
  'jira':          { backend: '1password',       vault: 'smd_agora_shared', item: 'jira-oauth-token' },
  'circleci':      { backend: '1password',       vault: 'smd_agora_shared', item: 'circleci-api-token' },
  'ssh-ca':        { backend: 'secrets-manager', secretId: 'locksmith/ssh/ca' },
};

// Resolve a real credential for a service
// This is the ONLY function in the entire system that touches plaintext credentials
// The returned value must NEVER be logged, stored to disk, or returned to a client
export async function resolveCredential(service) {
  const source = CREDENTIAL_SOURCES[service];
  if (!source) {
    throw new Error(`No credential source configured for service: ${service}`);
  }

  if (source.backend === 'secrets-manager') {
    return resolveFromSecretsManager(source.secretId);
  }

  if (source.backend === '1password') {
    return resolveFrom1Password(source.vault, source.item);
  }

  throw new Error(`Unknown credential backend: ${source.backend}`);
}

async function resolveFromSecretsManager(secretId) {
  const response = await smClient.send(
    new GetSecretValueCommand({ SecretId: secretId })
  );

  if (response.SecretString) {
    try {
      // Secrets Manager stores JSON - parse it
      return JSON.parse(response.SecretString);
    } catch {
      // Or plain string
      return { value: response.SecretString };
    }
  }

  throw new Error(`Secret ${secretId} has no string value`);
}

async function resolveFrom1Password(vault, item) {
  // 1Password Connect Server API
  // In production, CONNECT_HOST and CONNECT_TOKEN come from environment via op run
  const connectHost = process.env.OP_CONNECT_HOST;
  const connectToken = process.env.OP_CONNECT_TOKEN;

  if (!connectHost || !connectToken) {
    throw new Error('1Password Connect Server not configured (OP_CONNECT_HOST, OP_CONNECT_TOKEN)');
  }

  // First, find the vault ID
  const vaultsRes = await fetch(`${connectHost}/v1/vaults?filter=name eq "${vault}"`, {
    headers: { Authorization: `Bearer ${connectToken}` },
  });
  const vaults = await vaultsRes.json();
  if (!vaults.length) throw new Error(`Vault not found: ${vault}`);
  const vaultId = vaults[0].id;

  // Then find the item
  const itemsRes = await fetch(`${connectHost}/v1/vaults/${vaultId}/items?filter=title eq "${item}"`, {
    headers: { Authorization: `Bearer ${connectToken}` },
  });
  const items = await itemsRes.json();
  if (!items.length) throw new Error(`Item not found: ${item} in vault ${vault}`);

  // Get full item with field values
  const fullItemRes = await fetch(`${connectHost}/v1/vaults/${vaultId}/items/${items[0].id}`, {
    headers: { Authorization: `Bearer ${connectToken}` },
  });
  const fullItem = await fullItemRes.json();

  // Extract credential fields
  const credential = {};
  for (const field of fullItem.fields || []) {
    if (field.value) {
      credential[field.label || field.id] = field.value;
    }
  }

  return credential;
}
