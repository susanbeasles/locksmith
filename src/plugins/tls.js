import acme from 'acme-client';
import { generateKeyPairSync, createPrivateKey } from 'crypto';
import {
  SecretsManagerClient,
  PutSecretValueCommand,
  GetSecretValueCommand,
  CreateSecretCommand,
} from '@aws-sdk/client-secrets-manager';
import { config } from '../config.js';
import { credentialFingerprint, logAuditEvent } from '../utils/audit.js';

const smClient = new SecretsManagerClient({ region: config.aws.region });

// Let's Encrypt ACME directories
const ACME_DIRECTORIES = {
  production: 'https://acme-v02.api.letsencrypt.org/directory',
  staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
};

// Environment-specific cert configurations
const CERT_CONFIGS = {
  prod: {
    domains: ['sonarmd.com', '*.sonarmd.com'],
    acmeEnv: 'production',
    secretId: 'locksmith/tls/prod',
    dnsProvider: 'cloudflare',
  },
  dev: {
    domains: ['*.dev.sonarmd.com'],
    acmeEnv: 'production',
    secretId: 'locksmith/tls/dev',
    dnsProvider: 'cloudflare',
  },
  staging: {
    domains: ['*.staging.sonarmd.com'],
    acmeEnv: 'production',
    secretId: 'locksmith/tls/staging',
    dnsProvider: 'cloudflare',
  },
};

// Issue or renew a wildcard certificate via Let's Encrypt
export async function issueCertificate({ environment, forceRenew = false, triggeredBy }) {
  const certConfig = CERT_CONFIGS[environment];
  if (!certConfig) {
    throw new Error(`Unknown environment: ${environment}. Available: ${Object.keys(CERT_CONFIGS).join(', ')}`);
  }

  logAuditEvent({
    event_type: 'tls_cert_issuance_started',
    environment,
    domains: certConfig.domains,
    triggered_by: triggeredBy,
  });

  // Check if current cert is still valid and doesn't need renewal
  if (!forceRenew) {
    const existing = await getCurrentCert(certConfig.secretId);
    if (existing && !needsRenewal(existing)) {
      return {
        status: 'current',
        message: 'Certificate is still valid and does not need renewal',
        expiresAt: existing.expiresAt,
        daysRemaining: existing.daysRemaining,
        fingerprint: existing.fingerprint,
      };
    }
  }

  // Step 1: Create or load ACME account key
  const accountKey = await getOrCreateAccountKey();

  // Step 2: Initialize ACME client
  const client = new acme.Client({
    directoryUrl: ACME_DIRECTORIES[certConfig.acmeEnv],
    accountKey,
  });

  // Step 3: Register account (idempotent)
  await client.createAccount({
    termsOfServiceAgreed: true,
    contact: [`mailto:engineering@sonarmd.com`],
  });

  // Step 4: Generate CSR private key (this is the cert's private key)
  const [certKey, certCsr] = await acme.crypto.createCsr({
    altNames: certConfig.domains,
  });

  // Step 5: Request certificate with DNS-01 challenge
  const cert = await client.auto({
    csr: certCsr,
    email: 'engineering@sonarmd.com',
    termsOfServiceAgreed: true,
    challengeCreateFn: async (authz, challenge, keyAuthorization) => {
      if (challenge.type !== 'dns-01') return;

      const dnsRecord = `_acme-challenge.${authz.identifier.value}`;
      const recordValue = keyAuthorization;

      logAuditEvent({
        event_type: 'tls_dns_challenge_create',
        domain: authz.identifier.value,
        record: dnsRecord,
      });

      await createDnsRecord(certConfig.dnsProvider, dnsRecord, recordValue);

      // Wait for DNS propagation
      await sleep(15000);
    },
    challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
      if (challenge.type !== 'dns-01') return;

      const dnsRecord = `_acme-challenge.${authz.identifier.value}`;

      logAuditEvent({
        event_type: 'tls_dns_challenge_cleanup',
        domain: authz.identifier.value,
        record: dnsRecord,
      });

      await removeDnsRecord(certConfig.dnsProvider, dnsRecord);
    },
    challengePriority: ['dns-01'],
  });

  // Step 6: Store cert + key in Secrets Manager
  const certBundle = {
    certificate: cert.toString(),
    privateKey: certKey.toString(),
    domains: certConfig.domains,
    environment,
    issuedAt: new Date().toISOString(),
    // Let's Encrypt certs are valid for 90 days
    expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
    issuer: 'letsencrypt',
  };

  await storeCertInSecretsManager(certConfig.secretId, certBundle);

  logAuditEvent({
    event_type: 'tls_cert_issued',
    environment,
    domains: certConfig.domains,
    expires_at: certBundle.expiresAt,
    cert_fingerprint: credentialFingerprint(cert.toString()),
    triggered_by: triggeredBy,
  });

  return {
    status: 'issued',
    environment,
    domains: certConfig.domains,
    issuedAt: certBundle.issuedAt,
    expiresAt: certBundle.expiresAt,
    fingerprint: credentialFingerprint(cert.toString()),
    secretId: certConfig.secretId,
  };
}

// Push certificate to ACM for ALB/CloudFront/API Gateway
export async function pushToAcm({ environment, region }) {
  const certConfig = CERT_CONFIGS[environment];
  if (!certConfig) throw new Error(`Unknown environment: ${environment}`);

  const certBundle = await getCertBundle(certConfig.secretId);
  if (!certBundle) throw new Error('No certificate found. Issue one first.');

  const targetRegion = region || config.aws.region;

  // ACM import - dynamic import to avoid loading if not needed
  const { ACMClient, ImportCertificateCommand } = await import('@aws-sdk/client-acm');
  const acmClient = new ACMClient({ region: targetRegion });

  // Split certificate chain (cert + intermediates)
  const certParts = splitCertChain(certBundle.certificate);

  const params = {
    Certificate: Buffer.from(certParts.leaf),
    PrivateKey: Buffer.from(certBundle.privateKey),
  };

  if (certParts.chain) {
    params.CertificateChain = Buffer.from(certParts.chain);
  }

  // If we have an existing ACM ARN, reimport to the same ARN
  if (certBundle.acmArn && certBundle.acmArn[targetRegion]) {
    params.CertificateArn = certBundle.acmArn[targetRegion];
  }

  const result = await acmClient.send(new ImportCertificateCommand(params));

  // Store the ACM ARN back in the cert bundle for future reimports
  certBundle.acmArn = certBundle.acmArn || {};
  certBundle.acmArn[targetRegion] = result.CertificateArn;
  await storeCertInSecretsManager(certConfig.secretId, certBundle);

  logAuditEvent({
    event_type: 'tls_cert_pushed_acm',
    environment,
    region: targetRegion,
    acm_arn: result.CertificateArn,
  });

  return {
    acmArn: result.CertificateArn,
    region: targetRegion,
    environment,
  };
}

// Push certificate to servers via SSM Run Command
export async function pushToServers({ environment, instanceIds, certPath, keyPath }) {
  const certConfig = CERT_CONFIGS[environment];
  if (!certConfig) throw new Error(`Unknown environment: ${environment}`);

  const certBundle = await getCertBundle(certConfig.secretId);
  if (!certBundle) throw new Error('No certificate found. Issue one first.');

  const { SSMClient, SendCommandCommand } = await import('@aws-sdk/client-ssm');
  const ssmClient = new SSMClient({ region: config.aws.region });

  const targetCertPath = certPath || '/etc/ssl/certs/sonarmd.crt';
  const targetKeyPath = keyPath || '/etc/ssl/private/sonarmd.key';

  // Use SSM to write cert files and reload services
  // The cert content goes through SSM SecureString parameter, NOT as a command argument
  const commands = [
    // Write cert (fetched from Secrets Manager on the instance)
    `aws secretsmanager get-secret-value --secret-id ${certConfig.secretId} --region ${config.aws.region} --query SecretString --output text | python3 -c "import sys,json; d=json.load(sys.stdin); open('${targetCertPath}','w').write(d['certificate'])"`,
    `aws secretsmanager get-secret-value --secret-id ${certConfig.secretId} --region ${config.aws.region} --query SecretString --output text | python3 -c "import sys,json; d=json.load(sys.stdin); open('${targetKeyPath}','w').write(d['privateKey'])"`,
    // Set permissions
    `chmod 644 ${targetCertPath}`,
    `chmod 600 ${targetKeyPath}`,
    `chown root:root ${targetCertPath} ${targetKeyPath}`,
    // Reload services that use the cert
    `systemctl reload nginx 2>/dev/null || true`,
    `systemctl reload apache2 2>/dev/null || true`,
    `systemctl reload httpd 2>/dev/null || true`,
  ];

  const result = await ssmClient.send(new SendCommandCommand({
    InstanceIds: instanceIds,
    DocumentName: 'AWS-RunShellScript',
    Parameters: { commands },
    TimeoutSeconds: 60,
  }));

  logAuditEvent({
    event_type: 'tls_cert_pushed_servers',
    environment,
    instance_count: instanceIds.length,
    instance_ids: instanceIds,
    command_id: result.Command.CommandId,
  });

  return {
    commandId: result.Command.CommandId,
    instanceIds,
    environment,
    message: `Certificate push initiated to ${instanceIds.length} instances. Check SSM command status for results.`,
  };
}

// Get certificate status for an environment
export async function getCertStatus(environment) {
  const certConfig = CERT_CONFIGS[environment];
  if (!certConfig) throw new Error(`Unknown environment: ${environment}`);

  const certBundle = await getCertBundle(certConfig.secretId);
  if (!certBundle) {
    return {
      environment,
      status: 'missing',
      domains: certConfig.domains,
    };
  }

  const expiresAt = new Date(certBundle.expiresAt);
  const now = new Date();
  const daysRemaining = Math.floor((expiresAt - now) / (24 * 60 * 60 * 1000));

  let status = 'valid';
  if (daysRemaining <= 0) status = 'expired';
  else if (daysRemaining <= 30) status = 'expiring_soon';

  return {
    environment,
    status,
    domains: certBundle.domains,
    issuedAt: certBundle.issuedAt,
    expiresAt: certBundle.expiresAt,
    daysRemaining,
    issuer: certBundle.issuer,
    fingerprint: credentialFingerprint(certBundle.certificate),
    acmArns: certBundle.acmArn || {},
  };
}

// Get status for all environments
export async function getAllCertStatus() {
  const results = {};
  for (const env of Object.keys(CERT_CONFIGS)) {
    try {
      results[env] = await getCertStatus(env);
    } catch (err) {
      results[env] = { environment: env, status: 'error', error: err.message };
    }
  }
  return results;
}

// --- Cloudflare DNS helpers ---

async function createDnsRecord(provider, name, value) {
  if (provider !== 'cloudflare') {
    throw new Error(`DNS provider ${provider} not implemented. Only cloudflare is supported.`);
  }

  const cfApiToken = process.env.CLOUDFLARE_API_TOKEN;
  const cfZoneId = process.env.CLOUDFLARE_ZONE_ID;

  if (!cfApiToken || !cfZoneId) {
    throw new Error('CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID required for DNS-01 challenge');
  }

  // Create TXT record
  const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${cfZoneId}/dns_records`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${cfApiToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      type: 'TXT',
      name,
      content: value,
      ttl: 120,
    }),
  });

  const data = await res.json();
  if (!data.success) {
    throw new Error(`Cloudflare DNS record creation failed: ${JSON.stringify(data.errors)}`);
  }

  return data.result.id;
}

async function removeDnsRecord(provider, name) {
  if (provider !== 'cloudflare') return;

  const cfApiToken = process.env.CLOUDFLARE_API_TOKEN;
  const cfZoneId = process.env.CLOUDFLARE_ZONE_ID;
  if (!cfApiToken || !cfZoneId) return;

  // Find the TXT record
  const listRes = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${cfZoneId}/dns_records?type=TXT&name=${name}`,
    { headers: { Authorization: `Bearer ${cfApiToken}` } }
  );
  const listData = await listRes.json();

  // Delete all matching records
  for (const record of listData.result || []) {
    await fetch(
      `https://api.cloudflare.com/client/v4/zones/${cfZoneId}/dns_records/${record.id}`,
      { method: 'DELETE', headers: { Authorization: `Bearer ${cfApiToken}` } }
    );
  }
}

// --- Secrets Manager helpers ---

async function getCertBundle(secretId) {
  try {
    const response = await smClient.send(new GetSecretValueCommand({ SecretId: secretId }));
    return JSON.parse(response.SecretString);
  } catch (err) {
    if (err.name === 'ResourceNotFoundException') return null;
    throw err;
  }
}

async function storeCertInSecretsManager(secretId, bundle) {
  const secretString = JSON.stringify(bundle);

  try {
    await smClient.send(new PutSecretValueCommand({
      SecretId: secretId,
      SecretString: secretString,
    }));
  } catch (err) {
    if (err.name === 'ResourceNotFoundException') {
      // Secret doesn't exist yet, create it
      await smClient.send(new CreateSecretCommand({
        Name: secretId,
        SecretString: secretString,
        Description: `Locksmith TLS certificate for ${bundle.environment}`,
        Tags: [
          { Key: 'managed-by', Value: 'locksmith' },
          { Key: 'environment', Value: bundle.environment },
        ],
      }));
    } else {
      throw err;
    }
  }
}

async function getOrCreateAccountKey() {
  const secretId = 'locksmith/acme/account-key';

  try {
    const response = await smClient.send(new GetSecretValueCommand({ SecretId: secretId }));
    return response.SecretString;
  } catch (err) {
    if (err.name === 'ResourceNotFoundException') {
      // Generate new ACME account key
      const accountKey = await acme.crypto.createPrivateKey();
      const keyString = accountKey.toString();

      await smClient.send(new CreateSecretCommand({
        Name: secretId,
        SecretString: keyString,
        Description: 'Locksmith ACME account private key for Let\'s Encrypt',
        Tags: [{ Key: 'managed-by', Value: 'locksmith' }],
      }));

      return keyString;
    }
    throw err;
  }
}

function needsRenewal(certInfo) {
  return certInfo.daysRemaining <= 30;
}

function splitCertChain(fullChain) {
  const certs = fullChain.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!certs || certs.length === 0) {
    throw new Error('No certificates found in chain');
  }

  return {
    leaf: certs[0],
    chain: certs.length > 1 ? certs.slice(1).join('\n') : null,
  };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
