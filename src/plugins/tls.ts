import acme from 'acme-client';
import { createHash } from 'crypto';
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
const ACME_DIRECTORIES: Record<string, string> = {
  production: 'https://acme-v02.api.letsencrypt.org/directory',
  staging: 'https://acme-staging-v02.api.letsencrypt.org/directory',
};

interface CertConfig {
  domains: string[];
  acmeEnv: string;
  secretId: string;
  dnsProvider: string;
}

// Environment-specific cert configurations
const CERT_CONFIGS: Record<string, CertConfig> = {
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

interface CertBundle {
  certificate: string;
  privateKey: string;
  domains: string[];
  environment: string;
  issuedAt: string;
  expiresAt: string;
  issuer: string;
  acmArn?: Record<string, string>;
}

interface CertInfo {
  expiresAt: string;
  daysRemaining: number;
  fingerprint: string | null;
}

interface IssueCertParams {
  environment: string;
  forceRenew?: boolean;
  triggeredBy: string;
}

interface IssueCertResult {
  status: string;
  message?: string;
  environment?: string;
  domains?: string[];
  issuedAt?: string;
  expiresAt?: string;
  daysRemaining?: number;
  fingerprint?: string | null;
  secretId?: string;
}

interface PushToAcmParams {
  environment: string;
  region?: string;
}

interface PushToAcmResult {
  acmArn: string;
  region: string;
  environment: string;
}

interface PushToServersParams {
  environment: string;
  instanceIds: string[];
  certPath?: string;
  keyPath?: string;
}

interface PushToServersResult {
  commandId: string;
  instanceIds: string[];
  environment: string;
  message: string;
}

interface CertStatusResult {
  environment: string;
  status: string;
  domains?: string[];
  issuedAt?: string;
  expiresAt?: string;
  daysRemaining?: number;
  issuer?: string;
  fingerprint?: string | null;
  acmArns?: Record<string, string>;
  error?: string;
}

// Issue or renew a wildcard certificate via Let's Encrypt
export async function issueCertificate({
  environment,
  forceRenew = false,
  triggeredBy,
}: IssueCertParams): Promise<IssueCertResult> {
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
    contact: ['mailto:engineering@sonarmd.com'],
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
    challengeRemoveFn: async (authz, challenge, _keyAuthorization) => {
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
  const certBundle: CertBundle = {
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
export async function pushToAcm({
  environment,
  region,
}: PushToAcmParams): Promise<PushToAcmResult> {
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

  const importInput = {
    Certificate: Buffer.from(certParts.leaf),
    PrivateKey: Buffer.from(certBundle.privateKey),
    ...(certParts.chain ? { CertificateChain: Buffer.from(certParts.chain) } : {}),
    ...(certBundle.acmArn?.[targetRegion] ? { CertificateArn: certBundle.acmArn[targetRegion] } : {}),
  };

  const result = await acmClient.send(new ImportCertificateCommand(importInput));

  // Store the ACM ARN back in the cert bundle for future reimports
  certBundle.acmArn = certBundle.acmArn || {};
  certBundle.acmArn[targetRegion] = result.CertificateArn!;
  await storeCertInSecretsManager(certConfig.secretId, certBundle);

  logAuditEvent({
    event_type: 'tls_cert_pushed_acm',
    environment,
    region: targetRegion,
    acm_arn: result.CertificateArn,
  });

  return {
    acmArn: result.CertificateArn!,
    region: targetRegion,
    environment,
  };
}

// Push certificate to servers via SSM Run Command
export async function pushToServers({
  environment,
  instanceIds,
  certPath,
  keyPath,
}: PushToServersParams): Promise<PushToServersResult> {
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
    command_id: result.Command?.CommandId,
  });

  return {
    commandId: result.Command?.CommandId ?? '',
    instanceIds,
    environment,
    message: `Certificate push initiated to ${instanceIds.length} instances. Check SSM command status for results.`,
  };
}

// Get certificate status for an environment
export async function getCertStatus(environment: string): Promise<CertStatusResult> {
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
  const daysRemaining = Math.floor((expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));

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
export async function getAllCertStatus(): Promise<Record<string, CertStatusResult>> {
  const results: Record<string, CertStatusResult> = {};
  for (const env of Object.keys(CERT_CONFIGS)) {
    try {
      results[env] = await getCertStatus(env);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      results[env] = { environment: env, status: 'error', error: message };
    }
  }
  return results;
}

// --- Cloudflare DNS helpers ---

async function createDnsRecord(provider: string, name: string, value: string): Promise<string> {
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

  const data = await res.json() as { success: boolean; errors: unknown[]; result: { id: string } };
  if (!data.success) {
    throw new Error(`Cloudflare DNS record creation failed: ${JSON.stringify(data.errors)}`);
  }

  return data.result.id;
}

async function removeDnsRecord(provider: string, name: string): Promise<void> {
  if (provider !== 'cloudflare') return;

  const cfApiToken = process.env.CLOUDFLARE_API_TOKEN;
  const cfZoneId = process.env.CLOUDFLARE_ZONE_ID;
  if (!cfApiToken || !cfZoneId) return;

  // Find the TXT record
  const listRes = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${cfZoneId}/dns_records?type=TXT&name=${name}`,
    { headers: { Authorization: `Bearer ${cfApiToken}` } }
  );
  const listData = await listRes.json() as { result?: Array<{ id: string }> };

  // Delete all matching records
  for (const record of listData.result || []) {
    await fetch(
      `https://api.cloudflare.com/client/v4/zones/${cfZoneId}/dns_records/${record.id}`,
      { method: 'DELETE', headers: { Authorization: `Bearer ${cfApiToken}` } }
    );
  }
}

// --- Secrets Manager helpers ---

async function getCurrentCert(secretId: string): Promise<CertInfo | null> {
  const bundle = await getCertBundle(secretId);
  if (!bundle) return null;

  const expiresAt = new Date(bundle.expiresAt);
  const now = new Date();
  const daysRemaining = Math.floor((expiresAt.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));

  return {
    expiresAt: bundle.expiresAt,
    daysRemaining,
    fingerprint: credentialFingerprint(bundle.certificate),
  };
}

async function getCertBundle(secretId: string): Promise<CertBundle | null> {
  try {
    const response = await smClient.send(new GetSecretValueCommand({ SecretId: secretId }));
    return JSON.parse(response.SecretString!) as CertBundle;
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ResourceNotFoundException') return null;
    throw err;
  }
}

async function storeCertInSecretsManager(secretId: string, bundle: CertBundle): Promise<void> {
  const secretString = JSON.stringify(bundle);

  try {
    await smClient.send(new PutSecretValueCommand({
      SecretId: secretId,
      SecretString: secretString,
    }));
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ResourceNotFoundException') {
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

async function getOrCreateAccountKey(): Promise<string> {
  const secretId = 'locksmith/acme/account-key';

  try {
    const response = await smClient.send(new GetSecretValueCommand({ SecretId: secretId }));
    return response.SecretString!;
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'ResourceNotFoundException') {
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

function needsRenewal(certInfo: CertInfo): boolean {
  return certInfo.daysRemaining <= 30;
}

function splitCertChain(fullChain: string): { leaf: string; chain: string | null } {
  const certs = fullChain.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  if (!certs || certs.length === 0) {
    throw new Error('No certificates found in chain');
  }

  return {
    leaf: certs[0],
    chain: certs.length > 1 ? certs.slice(1).join('\n') : null,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
