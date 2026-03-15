import { Router } from 'express';
import {
  issueCertificate,
  pushToAcm,
  pushToServers,
  getCertStatus,
  getAllCertStatus,
} from '../plugins/tls.js';
import { requireAuthStrength } from '../middleware/auth.js';
import { logAuditEvent } from '../utils/audit.js';

const router = Router();

// GET /tls/status - Get cert status for all environments
router.get('/status', async (req, res) => {
  try {
    const status = await getAllCertStatus();
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /tls/status/:environment - Get cert status for one environment
router.get('/status/:environment', async (req, res) => {
  try {
    const status = await getCertStatus(req.params.environment);
    res.json(status);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// POST /tls/issue/:environment - Issue/renew a certificate
// This is a sensitive operation - requires FIDO2 for prod
router.post('/issue/:environment', async (req, res) => {
  const { environment } = req.params;
  const { force } = req.body;

  try {
    const result = await issueCertificate({
      environment,
      forceRenew: force === true,
      triggeredBy: `manual:${req.identity.oid}`,
    });

    res.json(result);
  } catch (err) {
    logAuditEvent({
      event_type: 'tls_cert_issue_error',
      environment,
      user: req.identity.oid,
      error: err.message,
    });

    res.status(500).json({ error: err.message });
  }
});

// POST /tls/push/acm/:environment - Push cert to ACM
router.post('/push/acm/:environment', async (req, res) => {
  try {
    const { region } = req.body;
    const result = await pushToAcm({
      environment: req.params.environment,
      region,
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /tls/push/servers/:environment - Push cert to EC2 instances via SSM
router.post('/push/servers/:environment', async (req, res) => {
  try {
    const { instanceIds, certPath, keyPath } = req.body;

    if (!instanceIds || !instanceIds.length) {
      return res.status(400).json({ error: 'instanceIds array is required' });
    }

    const result = await pushToServers({
      environment: req.params.environment,
      instanceIds,
      certPath,
      keyPath,
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /tls/renew-all - Renew all certs that need it and push everywhere
// The "one button to rule them all" endpoint
router.post('/renew-all', async (req, res) => {
  const results = {
    issued: [],
    skipped: [],
    pushed: [],
    errors: [],
  };

  const environments = ['prod', 'dev', 'staging'];

  for (const env of environments) {
    try {
      // Issue/renew
      const certResult = await issueCertificate({
        environment: env,
        forceRenew: false,
        triggeredBy: `renew-all:${req.identity.oid}`,
      });

      if (certResult.status === 'current') {
        results.skipped.push({
          environment: env,
          reason: 'still valid',
          expiresAt: certResult.expiresAt,
          daysRemaining: certResult.daysRemaining,
        });
      } else {
        results.issued.push(certResult);

        // Push to ACM in us-east-1 (CloudFront requires this region)
        try {
          const acmResult = await pushToAcm({ environment: env, region: 'us-east-1' });
          results.pushed.push({ type: 'acm', ...acmResult });
        } catch (err) {
          results.errors.push({ type: 'acm_push', environment: env, error: err.message });
        }

        // Also push to the primary region if different
        if (config.aws.region !== 'us-east-1') {
          try {
            const acmResult = await pushToAcm({ environment: env, region: config.aws.region });
            results.pushed.push({ type: 'acm', ...acmResult });
          } catch (err) {
            results.errors.push({ type: 'acm_push', environment: env, error: err.message });
          }
        }
      }
    } catch (err) {
      results.errors.push({ environment: env, error: err.message });
    }
  }

  logAuditEvent({
    event_type: 'tls_renew_all_completed',
    user: req.identity.oid,
    issued: results.issued.length,
    skipped: results.skipped.length,
    pushed: results.pushed.length,
    errors: results.errors.length,
  });

  res.json(results);
});

export default router;
