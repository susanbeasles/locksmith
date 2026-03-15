import express from 'express';
import { config } from './config.js';
import { requireAuth } from './middleware/auth.js';
import { initRedis } from './services/nonce.js';
import { initAuditLogger } from './utils/audit.js';

// Routes
import statusRoutes from './routes/status.js';
import nonceRoutes from './routes/nonce.js';
import proxyRoutes from './routes/proxy.js';
import rotateRoutes from './routes/rotate.js';
import sshRoutes from './routes/ssh.js';
import tlsRoutes from './routes/tls.js';

const app = express();
app.use(express.json());

// Trust ALB proxy headers
app.set('trust proxy', true);

// --- Unauthenticated routes ---
app.use('/', statusRoutes);

// --- Authenticated routes (require Entra ID token) ---
app.use('/nonce', requireAuth, nonceRoutes);
app.use('/proxy', requireAuth, proxyRoutes);
app.use('/rotate', requireAuth, rotateRoutes);
app.use('/ssh', requireAuth, sshRoutes);
app.use('/tls', requireAuth, tlsRoutes);

// Global error handler - never leak internal details
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// --- Start ---
async function start() {
  await initAuditLogger();
  initRedis();

  app.listen(config.port, () => {
    console.log(`
  ╔═══════════════════════════════════════╗
  ║         LOCKSMITH v0.1.0              ║
  ║   Zero Trust Credential Lifecycle     ║
  ║   Token Substitution Proxy            ║
  ╠═══════════════════════════════════════╣
  ║   Port: ${String(config.port).padEnd(29)}║
  ║   Entra Tenant: ${(config.entra.tenantId || 'NOT SET').substring(0, 20).padEnd(20)}║
  ║   Redis: ${config.redis.host.padEnd(29)}║
  ╚═══════════════════════════════════════╝
    `);
  });
}

start().catch((err) => {
  console.error('[FATAL]', err);
  process.exit(1);
});
