import { Router, type Request, type Response } from 'express';
import { issueNonce, revokeAllNonces, getNoncePolicy } from '../services/nonce.js';
import { checkAnomaly } from '../services/anomaly.js';

const router = Router();

interface NonceRequestBody {
  service: string;
  scope: string | Record<string, string>;
}

// POST /nonce - Request a nonce for a target service
router.post('/', async (req: Request<object, unknown, NonceRequestBody>, res: Response) => {
  try {
    const { service, scope } = req.body;

    if (!service) {
      res.status(400).json({ error: 'service is required' });
      return;
    }
    if (!scope) {
      res.status(400).json({ error: 'scope is required (what are you trying to do?)' });
      return;
    }

    // Check for anomalies before issuing
    const anomalyResult = await checkAnomaly({
      userId: req.identity.oid,
      service,
      scope,
      accessMethod: 'mcp_tool',
      deviceId: req.identity.deviceId ?? undefined,
      ip: req.ip ?? '',
    });

    if (anomalyResult.anomalous && anomalyResult.severity === 'high') {
      res.status(403).json({
        error: 'Access denied: anomalous behavior detected. Re-authenticate with hardware key.',
        anomaly: anomalyResult,
      });
      return;
    }

    const nonce = await issueNonce({
      userId: req.identity.oid,
      service,
      scope,
      deviceId: req.identity.deviceId ?? undefined,
    });

    // Include anomaly warning if medium severity
    const response: Record<string, unknown> = { ...nonce };
    if (anomalyResult.anomalous) {
      response.warning = 'Unusual access pattern detected. This has been logged.';
    }

    res.json(response);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: message });
  }
});

// DELETE /nonce - Revoke all active nonces for the authenticated user
router.delete('/', async (req: Request, res: Response) => {
  try {
    const revoked = await revokeAllNonces(req.identity.oid);
    res.json({ revoked, message: `${revoked} nonces revoked` });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: message });
  }
});

// GET /nonce/policy/:service - Get nonce policy for a service
router.get('/policy/:service', (req: Request<{ service: string }>, res: Response) => {
  const policy = getNoncePolicy(req.params.service);
  res.json({ service: req.params.service, policy });
});

export default router;
