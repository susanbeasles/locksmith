import { Router } from 'express';

const router = Router();

// GET /health - Unauthenticated health check for ALB
router.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'locksmith', version: '0.1.0' });
});

// GET /status - Authenticated status check with system info
router.get('/status', (req, res) => {
  res.json({
    status: 'ok',
    service: 'locksmith',
    version: '0.1.0',
    user: req.identity?.oid || 'unauthenticated',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
  });
});

export default router;
