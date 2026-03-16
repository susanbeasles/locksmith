import { Router, type Request, type Response } from 'express';

const router = Router();

// GET /health - Unauthenticated health check for ALB
router.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'locksmith', version: '0.2.0' });
});

// GET /status - Authenticated status check with system info
router.get('/status', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'locksmith',
    version: '0.2.0',
    user: req.identity?.oid || 'unauthenticated',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
  });
});

export default router;
