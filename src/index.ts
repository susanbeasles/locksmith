import express, { type Request, type Response, type NextFunction } from 'express';
import { config } from './config.js';
import { requireAuth } from './middleware/auth.js';
import { initAuditLogger } from './utils/audit.js';

// Import type augmentation so req.identity is recognized
import './types.js';

// Routes
import statusRoutes from './routes/status.js';
import nonceRoutes from './routes/nonce.js';
import proxyRoutes from './routes/proxy.js';
import rotateRoutes from './routes/rotate.js';
import sshRoutes from './routes/ssh.js';
import tlsRoutes from './routes/tls.js';

export const app = express();
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
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// --- Start ---
async function start(): Promise<void> {
  await initAuditLogger();

  app.listen(config.port, () => {
    console.log(`
  ╔═══════════════════════════════════════╗
  ║         LOCKSMITH v0.2.0              ║
  ║   Zero Trust Credential Lifecycle     ║
  ║   Token Substitution Proxy            ║
  ╠═══════════════════════════════════════╣
  ║   Port: ${String(config.port).padEnd(29)}║
  ║   Entra Tenant: ${(config.entra.tenantId || 'NOT SET').substring(0, 20).padEnd(20)}║
  ║   DynamoDB: ${config.dynamodb.noncesTable.padEnd(25)}║
  ╚═══════════════════════════════════════╝
    `);
  });
}

start().catch((err: unknown) => {
  console.error('[FATAL]', err);
  process.exit(1);
});
