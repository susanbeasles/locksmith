import { Router, type Request, type Response } from 'express';
import {
  issueCertificate,
  pushToAcm,
  pushToServers,
  getCertStatus,
  getAllCertStatus,
} from '../plugins/tls.js';
import { logAuditEvent } from '../utils/audit.js';
import { config } from '../config.js';

const router = Router();

interface IssueCertBody {
  force?: boolean;
}

interface PushAcmBody {
  region?: string;
}

interface PushServersBody {
  instanceIds?: string[];
  certPath?: string;
  keyPath?: string;
}

interface RenewAllResult {
  issued: Record<string, unknown>[];
  skipped: Record<string, unknown>[];
  pushed: Record<string, unknown>[];
  errors: Record<string, unknown>[];
}

// GET /tls/status - Get cert status for all environments
router.get('/status', async (_req: Request, res: Response) => {
  try {
    const status = await getAllCertStatus();
    res.json(status);
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: errMessage });
  }
});

// GET /tls/status/:environment - Get cert status for one environment
router.get('/status/:environment', async (req: Request<{ environment: string }>, res: Response) => {
  try {
    const status = await getCertStatus(req.params.environment);
    res.json(status);
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    res.status(400).json({ error: errMessage });
  }
});

// POST /tls/issue/:environment - Issue/renew a certificate
// This is a sensitive operation - requires FIDO2 for prod
router.post('/issue/:environment', async (req: Request<{ environment: string }, unknown, IssueCertBody>, res: Response) => {
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
    const errMessage = err instanceof Error ? err.message : String(err);
    logAuditEvent({
      event_type: 'tls_cert_issue_error',
      environment,
      user: req.identity.oid,
      error: errMessage,
    });

    res.status(500).json({ error: errMessage });
  }
});

// POST /tls/push/acm/:environment - Push cert to ACM
router.post('/push/acm/:environment', async (req: Request<{ environment: string }, unknown, PushAcmBody>, res: Response) => {
  try {
    const { region } = req.body;
    const result = await pushToAcm({
      environment: req.params.environment,
      region,
    });

    res.json(result);
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: errMessage });
  }
});

// POST /tls/push/servers/:environment - Push cert to EC2 instances via SSM
router.post('/push/servers/:environment', async (req: Request<{ environment: string }, unknown, PushServersBody>, res: Response) => {
  try {
    const { instanceIds, certPath, keyPath } = req.body;

    if (!instanceIds || !instanceIds.length) {
      res.status(400).json({ error: 'instanceIds array is required' });
      return;
    }

    const result = await pushToServers({
      environment: req.params.environment,
      instanceIds,
      certPath,
      keyPath,
    });

    res.json(result);
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: errMessage });
  }
});

// POST /tls/renew-all - Renew all certs that need it and push everywhere
// The "one button to rule them all" endpoint
router.post('/renew-all', async (req: Request, res: Response) => {
  const results: RenewAllResult = {
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
        results.issued.push(certResult as unknown as Record<string, unknown>);

        // Push to ACM in us-east-1 (CloudFront requires this region)
        try {
          const acmResult = await pushToAcm({ environment: env, region: 'us-east-1' });
          results.pushed.push({ type: 'acm', ...acmResult });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          results.errors.push({ type: 'acm_push', environment: env, error: msg });
        }

        // Also push to the primary region if different
        if (config.aws.region !== 'us-east-1') {
          try {
            const acmResult = await pushToAcm({ environment: env, region: config.aws.region });
            results.pushed.push({ type: 'acm', ...acmResult });
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            results.errors.push({ type: 'acm_push', environment: env, error: msg });
          }
        }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      results.errors.push({ environment: env, error: msg });
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
