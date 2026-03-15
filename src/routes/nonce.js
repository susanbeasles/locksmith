import { Router } from 'express';
import { issueNonce, revokeAllNonces, getNoncePolicy } from '../services/nonce.js';
import { checkAnomaly } from '../services/anomaly.js';

const router = Router();

// POST /nonce - Request a nonce for a target service
router.post('/', async (req, res) => {
  try {
    const { service, scope } = req.body;

    if (!service) {
      return res.status(400).json({ error: 'service is required' });
    }
    if (!scope) {
      return res.status(400).json({ error: 'scope is required (what are you trying to do?)' });
    }

    // Check for anomalies before issuing
    const anomalyResult = await checkAnomaly({
      userId: req.identity.oid,
      service,
      scope,
      accessMethod: 'mcp_tool',
      deviceId: req.identity.deviceId,
      ip: req.ip,
    });

    if (anomalyResult.anomalous && anomalyResult.severity === 'high') {
      return res.status(403).json({
        error: 'Access denied: anomalous behavior detected. Re-authenticate with hardware key.',
        anomaly: anomalyResult,
      });
    }

    const nonce = await issueNonce({
      userId: req.identity.oid,
      service,
      scope,
      deviceId: req.identity.deviceId,
    });

    // Include anomaly warning if medium severity
    const response = { ...nonce };
    if (anomalyResult.anomalous) {
      response.warning = 'Unusual access pattern detected. This has been logged.';
    }

    res.json(response);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /nonce - Revoke all active nonces for the authenticated user
router.delete('/', async (req, res) => {
  try {
    const revoked = await revokeAllNonces(req.identity.oid);
    res.json({ revoked, message: `${revoked} nonces revoked` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /nonce/policy/:service - Get nonce policy for a service
router.get('/policy/:service', (req, res) => {
  const policy = getNoncePolicy(req.params.service);
  res.json({ service: req.params.service, policy });
});

export default router;
