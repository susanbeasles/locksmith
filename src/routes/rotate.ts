import { Router, type Request, type Response } from 'express';
import { rotateAccessKeys } from '../plugins/aws.js';
import { logAuditEvent } from '../utils/audit.js';

type RotationPlugin = (params: Record<string, unknown>) => Promise<Record<string, unknown>>;

const router = Router();

// Plugin registry - maps service names to rotation functions
const ROTATION_PLUGINS: Record<string, RotationPlugin> = {
  'aws-iam': rotateAccessKeys as unknown as RotationPlugin,
  // Phase 2: github, mongodb-atlas, postgres, circleci, sentry, slack, etc.
};

interface RotateRequestBody {
  target?: string;
  [key: string]: unknown;
}

// POST /rotate/:service - Trigger credential rotation
router.post('/:service', async (req: Request<{ service: string }, unknown, RotateRequestBody>, res: Response) => {
  const { service } = req.params;
  const { target } = req.body; // e.g., IAM username, GitHub app name

  const plugin = ROTATION_PLUGINS[service];
  if (!plugin) {
    res.status(404).json({
      error: `No rotation plugin for: ${service}`,
      available: Object.keys(ROTATION_PLUGINS),
    });
    return;
  }

  if (!target) {
    res.status(400).json({ error: 'target is required (e.g., IAM username)' });
    return;
  }

  try {
    const result = await plugin({
      ...req.body,
      triggeredBy: `manual:${req.identity.oid}`,
    });

    res.json(result);
  } catch (err) {
    const errMessage = err instanceof Error ? err.message : String(err);
    logAuditEvent({
      event_type: 'rotation_error',
      service,
      target,
      user: req.identity.oid,
      error: errMessage,
    });

    res.status(500).json({ error: errMessage });
  }
});

// GET /rotate - List available rotation plugins
router.get('/', (_req: Request, res: Response) => {
  res.json({
    plugins: Object.keys(ROTATION_PLUGINS),
    message: 'POST /rotate/:service with { target } to trigger rotation',
  });
});

export default router;
