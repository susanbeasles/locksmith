import { randomBytes } from 'crypto';
import { execSync } from 'child_process';
import { writeFileSync, unlinkSync, readFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { config } from '../config.js';
import { credentialFingerprint, logAuditEvent } from '../utils/audit.js';
import { resolveCredential } from '../services/credentials.js';

// Default certificate validity
const DEFAULT_VALIDITY_SECONDS = 8 * 60 * 60; // 8 hours
const MAX_VALIDITY_SECONDS = 24 * 60 * 60;    // 24 hours hard cap

// Principal mappings - which users can request certs for which principals
// In production, this comes from policy config
const PRINCIPAL_POLICY: Record<string, string[]> = {
  // Entra OID -> allowed SSH principals
  // '*' means any authenticated user can request these principals
  '*': ['deploy', 'ubuntu', 'ec2-user'],
  // Specific user overrides (add Entra OIDs here)
  // 'oid-for-tony': ['root', 'deploy', 'ubuntu', 'ec2-user', 'admin'],
};

interface IssueCertificateParams {
  userId: string;
  principals?: string[];
  validitySeconds?: number;
  keyId?: string;
  extensions?: string[];
  triggeredBy?: string;
}

interface IssueCertificateResult {
  certificate: string;
  privateKey: string;
  publicKey: string;
  keyId: string;
  principals: string[];
  validitySeconds: number;
  expiresAt: string;
  usage: {
    addToAgent: string;
    sshCommand: string;
  };
}

interface RotateCaKeyParams {
  triggeredBy: string;
}

interface RotateCaKeyResult {
  privateKey: string;
  publicKey: string;
  fingerprint: string | null;
  instructions: string[];
}

// Issue a short-lived SSH certificate
export async function issueCertificate({
  userId,
  principals,
  validitySeconds = DEFAULT_VALIDITY_SECONDS,
  keyId,
  extensions,
  triggeredBy,
}: IssueCertificateParams): Promise<IssueCertificateResult> {
  // Enforce max validity
  if (validitySeconds > MAX_VALIDITY_SECONDS) {
    throw new Error(`Validity cannot exceed ${MAX_VALIDITY_SECONDS}s (${MAX_VALIDITY_SECONDS / 3600}h)`);
  }

  // Validate principals against policy
  const allowedPrincipals = getAllowedPrincipals(userId);
  const requestedPrincipals = principals || ['deploy'];
  for (const p of requestedPrincipals) {
    if (!allowedPrincipals.includes(p) && !allowedPrincipals.includes('*')) {
      throw new Error(`Principal '${p}' not allowed for this user. Allowed: ${allowedPrincipals.join(', ')}`);
    }
  }

  // Generate an ephemeral keypair for the user
  // This keypair exists only for the duration of this certificate
  const tempDir = join(tmpdir(), `locksmith-ssh-${randomBytes(8).toString('hex')}`);
  mkdirSync(tempDir, { recursive: true });

  const userKeyPath = join(tempDir, 'user_key');
  const userPubPath = `${userKeyPath}.pub`;
  const certPath = `${userKeyPath}-cert.pub`;
  const caKeyPath = join(tempDir, 'ca_key');

  try {
    // Step 1: Generate ephemeral user keypair
    execSync(`ssh-keygen -t ed25519 -f ${userKeyPath} -N "" -q`, { stdio: 'pipe' });

    // Step 2: Retrieve CA private key from credential store
    // The CA key NEVER leaves this function's scope
    const caCredential = await resolveCredential('ssh-ca') as Record<string, string>;
    const caPrivateKey = caCredential.private_key || caCredential.password || caCredential.value;

    if (!caPrivateKey) {
      throw new Error('SSH CA private key not found in credential store');
    }

    // Write CA key to temp file (we'll shred it immediately after signing)
    writeFileSync(caKeyPath, caPrivateKey, { mode: 0o600 });

    // Step 3: Sign the user's public key with the CA
    const certKeyId = keyId || `locksmith:${userId}:${Date.now()}`;
    const principalsList = requestedPrincipals.join(',');
    const validitySpec = `+${validitySeconds}s`;

    // Build ssh-keygen sign command
    const signCmd: string[] = [
      'ssh-keygen',
      '-s', caKeyPath,                    // CA private key
      '-I', certKeyId,                    // Key identity (shows in logs)
      '-n', principalsList,              // Allowed principals
      '-V', validitySpec,                // Validity period
      '-z', Date.now().toString(),       // Serial number
    ];

    // Add extensions (default: standard user cert extensions)
    const certExtensions = extensions || [
      'permit-pty',
      'permit-port-forwarding',
      'permit-agent-forwarding',
    ];

    // ssh-keygen uses -O for extensions on user certs
    for (const ext of certExtensions) {
      signCmd.push('-O', `extension:${ext}`);
    }

    // No source-address restriction by default
    // In production, could bind to the user's known IP
    // signCmd.push('-O', `source-address:${userIp}/32`);

    signCmd.push(userPubPath);

    execSync(signCmd.join(' '), { stdio: 'pipe' });

    // Step 4: Read the signed certificate and the private key
    const certificate = readFileSync(certPath, 'utf-8').trim();
    const privateKey = readFileSync(userKeyPath, 'utf-8').trim();
    const publicKey = readFileSync(userPubPath, 'utf-8').trim();

    // Step 5: Immediately shred the CA key from temp
    try {
      // Overwrite with random data before unlinking
      writeFileSync(caKeyPath, randomBytes(4096));
      unlinkSync(caKeyPath);
    } catch {
      // Best effort
    }

    logAuditEvent({
      event_type: 'ssh_cert_issued',
      user: userId,
      key_id: certKeyId,
      principals: requestedPrincipals,
      validity_seconds: validitySeconds,
      expires_at: new Date(Date.now() + validitySeconds * 1000).toISOString(),
      public_key_fingerprint: credentialFingerprint(publicKey),
      triggered_by: triggeredBy || 'manual',
    });

    return {
      certificate,
      privateKey,
      publicKey,
      keyId: certKeyId,
      principals: requestedPrincipals,
      validitySeconds,
      expiresAt: new Date(Date.now() + validitySeconds * 1000).toISOString(),
      // Instructions for the client
      usage: {
        addToAgent: `echo '${privateKey.replace(/\n/g, '\\n')}' | ssh-add -t ${validitySeconds} -`,
        sshCommand: `ssh -o CertificateFile=<(echo '${certificate}') -i <(echo '${privateKey}') user@host`,
      },
    };
  } finally {
    // Cleanup: shred all temp files
    try {
      const files = [userKeyPath, userPubPath, certPath, caKeyPath];
      for (const f of files) {
        try {
          writeFileSync(f, randomBytes(4096)); // overwrite
        } catch { /* file may not exist */ }
        try {
          unlinkSync(f);
        } catch { /* already gone */ }
      }
      execSync(`rm -rf ${tempDir}`, { stdio: 'pipe' });
    } catch {
      // Best effort cleanup
    }
  }
}

// Get CA public key (safe to distribute to hosts)
export async function getCaPublicKey(): Promise<string> {
  const caCredential = await resolveCredential('ssh-ca') as Record<string, string>;
  const publicKey = caCredential.public_key;

  if (!publicKey) {
    throw new Error('SSH CA public key not found. Store it as the public_key field on the ssh-ca credential.');
  }

  return publicKey;
}

// Check what principals a user is allowed to request
function getAllowedPrincipals(userId: string): string[] {
  // Check user-specific policy first
  if (PRINCIPAL_POLICY[userId]) {
    return PRINCIPAL_POLICY[userId];
  }

  // Fall back to wildcard policy
  return PRINCIPAL_POLICY['*'] || [];
}

// Rotate the CA key itself (very sensitive operation)
export async function rotateCaKey({
  triggeredBy,
}: RotateCaKeyParams): Promise<RotateCaKeyResult> {
  logAuditEvent({
    event_type: 'ssh_ca_rotation_started',
    triggered_by: triggeredBy,
  });

  const tempDir = join(tmpdir(), `locksmith-ca-rotate-${randomBytes(8).toString('hex')}`);
  mkdirSync(tempDir, { recursive: true });
  const newCaKeyPath = join(tempDir, 'ca_key');

  try {
    // Generate new CA keypair
    execSync(`ssh-keygen -t ed25519 -f ${newCaKeyPath} -N "" -q -C "locksmith-ca-${Date.now()}"`, {
      stdio: 'pipe',
    });

    const newPrivateKey = readFileSync(newCaKeyPath, 'utf-8').trim();
    const newPublicKey = readFileSync(`${newCaKeyPath}.pub`, 'utf-8').trim();

    // The caller is responsible for storing this in the credential store
    // We return it here but it should go straight into Secrets Manager or 1Password
    // and the old CA public key should be kept in TrustedUserCAKeys on hosts
    // during a transition period

    logAuditEvent({
      event_type: 'ssh_ca_rotation_completed',
      new_ca_fingerprint: credentialFingerprint(newPublicKey),
      triggered_by: triggeredBy,
    });

    return {
      privateKey: newPrivateKey,
      publicKey: newPublicKey,
      fingerprint: credentialFingerprint(newPublicKey),
      instructions: [
        '1. Store the new CA private key in Secrets Manager (locksmith/ssh-ca)',
        '2. Store the new CA public key in the same secret',
        '3. Add the new CA public key to TrustedUserCAKeys on all target hosts',
        '4. Keep the old CA public key in TrustedUserCAKeys for the transition period',
        '5. After all existing certs expire (max 24h), remove the old CA public key',
      ],
    };
  } finally {
    try {
      writeFileSync(newCaKeyPath, randomBytes(4096));
      writeFileSync(`${newCaKeyPath}.pub`, randomBytes(4096));
      unlinkSync(newCaKeyPath);
      unlinkSync(`${newCaKeyPath}.pub`);
      execSync(`rm -rf ${tempDir}`, { stdio: 'pipe' });
    } catch { /* best effort */ }
  }
}
