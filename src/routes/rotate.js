import { Router } from 'express';
import { rotateAccessKeys } from '../plugins/aws.js';
import { logAuditEvent } from '../utils/audit.js';

const router = Router();

// Plugin registry - maps service names to rotation functions
const ROTATION_PLUGINS = {
  'aws-iam': rotateAccessKeys,
  // Phase 2: github, mongodb-atlas, postgres, circleci, sentry, slack, etc.
};

// POST /rotate/:service - Trigger credential rotation
router.post('/:service', async (req, res) => {
  const { service } = req.params;
  const { target } = req.body; // e.g., IAM username, GitHub app name

  const plugin = ROTATION_PLUGINS[service];
  if (!plugin) {
    return res.status(404).json({
      error: `No rotation plugin for: ${service}`,
      available: Object.keys(ROTATION_PLUGINS),
    });
  }

  if (!target) {
    return res.status(400).json({ error: 'target is required (e.g., IAM username)' });
  }

  try {
    const result = await plugin({
      ...req.body,
      triggeredBy: `manual:${req.identity.oid}`,
    });

    res.json(result);
  } catch (err) {
    logAuditEvent({
      event_type: 'rotation_error',
      service,
      target,
      user: req.identity.oid,
      error: err.message,
    });

    res.status(500).json({ error: err.message });
  }
});

// GET /rotate - List available rotation plugins
router.get('/', (req, res) => {
  res.json({
    plugins: Object.keys(ROTATION_PLUGINS),
    message: 'POST /rotate/:service with { target } to trigger rotation',
  });
});

export default router;
