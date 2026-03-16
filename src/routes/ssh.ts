import { Router, type Request, type Response } from 'express';
import { issueCertificate, getCaPublicKey, rotateCaKey } from '../plugins/ssh.js';
import { requireAuthStrength } from '../middleware/auth.js';
import { logAuditEvent } from '../utils/audit.js';

const router = Router();

interface SshCertRequestBody {
  principals?: string[];
  validity_seconds?: number;
  key_id?: string;
  extensions?: string[];
}

// POST /ssh/cert - Issue a short-lived SSH certificate
router.post('/cert', async (req: Request<object, unknown, SshCertRequestBody>, res: Response) => {
  try {
    const {
      principals,
      validity_seconds: validitySeconds,
      key_id: keyId,
      extensions,
    } = req.body;

    const result = await issueCertificate({
      userId: req.identity.oid,
      principals,
      validitySeconds,
      keyId,
      extensions,
      triggeredBy: `manual:${req.identity.oid}`,
    });

    res.json(result);
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    logAuditEvent({
      event_type: 'ssh_cert_error',
      user: req.identity.oid,
      error: errMessage,
    });

    res.status(400).json({ error: errMessage });
  }
});

// GET /ssh/ca - Get the CA public key (for configuring target hosts)
// This is safe to expose - it's the public key that goes in sshd_config
router.get('/ca', async (_req: Request, res: Response) => {
  try {
    const publicKey = await getCaPublicKey();
    res.type('text/plain').send(publicKey);
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: errMessage });
  }
});

// POST /ssh/ca/rotate - Rotate the CA key (requires FIDO2 auth)
router.post('/ca/rotate', requireAuthStrength('fido2'), async (req: Request, res: Response) => {
  try {
    const result = await rotateCaKey({
      triggeredBy: `manual:${req.identity.oid}`,
    });

    // WARNING: This response contains the new CA private key
    // It must be immediately stored in the credential store
    // This is the ONE time the private key is visible
    res.json(result);
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    logAuditEvent({
      event_type: 'ssh_ca_rotation_error',
      user: req.identity.oid,
      error: errMessage,
    });

    res.status(500).json({ error: errMessage });
  }
});

// GET /ssh/setup - Instructions for configuring target hosts
router.get('/setup', (_req: Request, res: Response) => {
  res.json({
    instructions: {
      step1: 'Get the CA public key: GET /ssh/ca',
      step2: 'On each target host, add to /etc/ssh/sshd_config:',
      sshd_config: [
        '# Trust Locksmith CA for user authentication',
        'TrustedUserCAKeys /etc/ssh/locksmith-ca.pub',
        '',
        '# Optional: restrict which principals are allowed',
        'AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u',
      ],
      step3: 'Write the CA public key to /etc/ssh/locksmith-ca.pub',
      step4: 'Create principal files for each user:',
      principal_example: 'echo "deploy" > /etc/ssh/auth_principals/deploy',
      step5: 'Restart sshd: systemctl restart sshd',
      step6: 'Test: POST /ssh/cert with { "principals": ["deploy"] }',
      ansible: 'Or use the Locksmith Ansible role to automate this across all hosts.',
    },
  });
});

export default router;
