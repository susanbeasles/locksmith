import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { Request, Response, NextFunction } from 'express';
import { config } from '../config.js';
import { logAuditEvent } from '../utils/audit.js';

// ---------------------------------------------------------------------------
// Express type augmentation — adds `req.identity`
// ---------------------------------------------------------------------------

interface RequestIdentity {
  sub: string;
  oid: string;
  name: string;
  email: string;
  groups: string[];
  deviceId: string | null;
  authStrength: string | null;
  tid: string;
}

declare module 'express' {
  interface Request {
    identity: RequestIdentity;
  }
}

// ---------------------------------------------------------------------------
// Entra ID JWT payload extension
// ---------------------------------------------------------------------------

interface EntraJWTPayload extends JWTPayload {
  oid?: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  groups?: string[];
  deviceid?: string;
  acrs?: string;
  tid?: string;
}

// ---------------------------------------------------------------------------
// JWKS singleton (jose v6 — createRemoteJWKSet returns a KeyLike resolver)
// ---------------------------------------------------------------------------

type JWKSResolver = ReturnType<typeof createRemoteJWKSet>;

let jwks: JWKSResolver | null = null;

function getJwks(): JWKSResolver {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(config.entra.jwksUri));
  }
  return jwks;
}

// ---------------------------------------------------------------------------
// Validate Entra ID OIDC bearer token
// ---------------------------------------------------------------------------

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.substring(7);

  try {
    const { payload } = await jwtVerify(token, getJwks(), {
      issuer: config.entra.issuer,
      audience: config.entra.clientId,
    });

    const entraPayload = payload as EntraJWTPayload;

    // Attach identity to request
    req.identity = {
      sub: entraPayload.sub ?? '',
      oid: entraPayload.oid ?? '',
      name: entraPayload.name ?? '',
      email: entraPayload.preferred_username ?? entraPayload.email ?? '',
      groups: entraPayload.groups ?? [],
      deviceId: entraPayload.deviceid ?? null,
      authStrength: entraPayload.acrs ?? null,
      tid: entraPayload.tid ?? '',
    };

    next();
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    logAuditEvent({
      event_type: 'auth_failure',
      error: message,
      ip: req.ip,
    });

    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------------------------------------------------------------------------
// Optional: require specific auth strength (e.g., FIDO2 for sensitive ops)
// ---------------------------------------------------------------------------

export function requireAuthStrength(
  requiredStrength: string,
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction): void => {
    // This checks the Entra Conditional Access authentication context.
    // In practice, Conditional Access enforces this before the token is issued.
    // This is defense-in-depth.
    if (requiredStrength === 'fido2' && req.identity.authStrength !== 'c1') {
      logAuditEvent({
        event_type: 'auth_strength_insufficient',
        user: req.identity.oid,
        required: requiredStrength,
        actual: req.identity.authStrength,
      });
      res.status(403).json({
        error: 'Phishing-resistant MFA required for this operation',
      });
      return;
    }
    next();
  };
}
