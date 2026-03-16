import {
  IAMClient,
  CreateAccessKeyCommand,
  DeleteAccessKeyCommand,
  ListAccessKeysCommand,
  type AccessKeyMetadata,
} from '@aws-sdk/client-iam';
import {
  STSClient,
  AssumeRoleCommand,
  GetCallerIdentityCommand,
  type AssumeRoleCommandInput,
} from '@aws-sdk/client-sts';
import { config } from '../config.js';
import { credentialFingerprint, logAuditEvent } from '../utils/audit.js';

const iam = new IAMClient({ region: config.aws.region });
const sts = new STSClient({ region: config.aws.region });

interface VendAwsSessionParams {
  roleArn: string;
  sessionName?: string;
  durationSeconds?: number;
  policy?: Record<string, unknown>;
}

interface VendAwsSessionResult {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: Date;
}

interface RotateAccessKeysParams {
  userName: string;
  triggeredBy: string;
}

interface RotateAccessKeysResult {
  success: boolean;
  service: string;
  target: string;
  newKeyFingerprint: string | null;
  revokedKeys: number;
}

// Vend a short-lived STS session for a proxy request
// This is Mode A: token vending for services that support derived credentials
export async function vendAwsSession({
  roleArn,
  sessionName,
  durationSeconds = 900,
  policy,
}: VendAwsSessionParams): Promise<VendAwsSessionResult> {
  const params: AssumeRoleCommandInput = {
    RoleArn: roleArn,
    RoleSessionName: sessionName || `locksmith-${Date.now()}`,
    DurationSeconds: durationSeconds,
  };

  // Optional: inline session policy to scope down permissions for this specific request
  if (policy) {
    params.Policy = JSON.stringify(policy);
  }

  const response = await sts.send(new AssumeRoleCommand(params));

  if (!response.Credentials) {
    throw new Error('STS AssumeRole returned no credentials');
  }

  return {
    accessKeyId: response.Credentials.AccessKeyId!,
    secretAccessKey: response.Credentials.SecretAccessKey!,
    sessionToken: response.Credentials.SessionToken!,
    expiration: response.Credentials.Expiration!,
  };
}

// Rotate IAM access keys for a user
// Full lifecycle: create new -> verify -> delete old
export async function rotateAccessKeys({
  userName,
  triggeredBy,
}: RotateAccessKeysParams): Promise<RotateAccessKeysResult> {
  logAuditEvent({
    event_type: 'rotation_started',
    service: 'aws-iam',
    target: userName,
    triggered_by: triggeredBy,
  });

  // Step 1: List existing keys
  const existingKeys = await iam.send(
    new ListAccessKeysCommand({ UserName: userName })
  );

  const activeKeys = (existingKeys.AccessKeyMetadata ?? []).filter(
    (k: AccessKeyMetadata) => k.Status === 'Active'
  );

  // AWS allows max 2 access keys per user
  // If there are already 2, we need to delete the oldest one first
  if (activeKeys.length >= 2) {
    const oldest = activeKeys.sort(
      (a: AccessKeyMetadata, b: AccessKeyMetadata) =>
        (a.CreateDate?.getTime() ?? 0) - (b.CreateDate?.getTime() ?? 0)
    )[0];

    await iam.send(
      new DeleteAccessKeyCommand({
        UserName: userName,
        AccessKeyId: oldest.AccessKeyId,
      })
    );

    logAuditEvent({
      event_type: 'rotation_deleted_excess_key',
      service: 'aws-iam',
      target: userName,
      old_key_fingerprint: credentialFingerprint(oldest.AccessKeyId ?? ''),
    });
  }

  // Step 2: Create new key
  const newKey = await iam.send(
    new CreateAccessKeyCommand({ UserName: userName })
  );

  if (!newKey.AccessKey) {
    throw new Error('CreateAccessKey returned no key');
  }

  const newAccessKeyId = newKey.AccessKey.AccessKeyId!;
  const newSecretKey = newKey.AccessKey.SecretAccessKey!;

  logAuditEvent({
    event_type: 'rotation_key_created',
    service: 'aws-iam',
    target: userName,
    new_key_fingerprint: credentialFingerprint(newAccessKeyId),
  });

  // Step 3: Verify the new key works
  // We use STS GetCallerIdentity as a lightweight verification
  const verifySts = new STSClient({
    region: config.aws.region,
    credentials: {
      accessKeyId: newAccessKeyId,
      secretAccessKey: newSecretKey,
    },
  });

  try {
    // New IAM keys can take a few seconds to propagate
    await new Promise(resolve => setTimeout(resolve, 5000));

    await verifySts.send(new GetCallerIdentityCommand({}));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    logAuditEvent({
      event_type: 'rotation_verification_failed',
      service: 'aws-iam',
      target: userName,
      new_key_fingerprint: credentialFingerprint(newAccessKeyId),
      error: message,
    });

    // Don't revoke old key - new one didn't verify
    throw new Error(`New access key verification failed: ${message}. Old key NOT revoked.`);
  }

  // Step 4: Delete remaining old keys (any active keys that aren't the new one)
  const remainingOldKeys = activeKeys.filter(
    (k: AccessKeyMetadata) => k.AccessKeyId !== newAccessKeyId
  );

  for (const oldKey of remainingOldKeys) {
    try {
      await iam.send(
        new DeleteAccessKeyCommand({
          UserName: userName,
          AccessKeyId: oldKey.AccessKeyId,
        })
      );

      logAuditEvent({
        event_type: 'rotation_old_key_revoked',
        service: 'aws-iam',
        target: userName,
        old_key_fingerprint: credentialFingerprint(oldKey.AccessKeyId ?? ''),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      logAuditEvent({
        event_type: 'rotation_revoke_failed',
        service: 'aws-iam',
        target: userName,
        old_key_fingerprint: credentialFingerprint(oldKey.AccessKeyId ?? ''),
        error: message,
      });
      // Don't throw - new key is working, old key revocation failure is not critical
    }
  }

  logAuditEvent({
    event_type: 'rotation_completed',
    service: 'aws-iam',
    target: userName,
    new_key_fingerprint: credentialFingerprint(newAccessKeyId),
    triggered_by: triggeredBy,
  });

  // Return metadata only. NEVER the credential values.
  return {
    success: true,
    service: 'aws-iam',
    target: userName,
    newKeyFingerprint: credentialFingerprint(newAccessKeyId),
    revokedKeys: remainingOldKeys.length,
  };
}
