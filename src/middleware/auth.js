import { createRemoteJWKSet, jwtVerify } from 'jose';
import { config } from '../config.js';
import { logAuditEvent } from '../utils/audit.js';

let jwks = null;

function getJwks() {
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(config.entra.jwksUri));
  }
  return jwks;
}

// Validate Entra ID OIDC bearer token
export async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.substring(7);

  try {
    const { payload } = await jwtVerify(token, getJwks(), {
      issuer: config.entra.issuer,
      audience: config.entra.clientId,
    });

    // Attach identity to request
    req.identity = {
      sub: payload.sub,
      oid: payload.oid,             // Entra object ID (stable user identifier)
      name: payload.name,
      email: payload.preferred_username || payload.email,
      groups: payload.groups || [],
      deviceId: payload.deviceid || null,
      authStrength: payload.acrs || null,  // Authentication context class reference
      tid: payload.tid,
    };

    next();
  } catch (err) {
    logAuditEvent({
      event_type: 'auth_failure',
      error: err.message,
      ip: req.ip,
    });

    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Optional: require specific auth strength (e.g., FIDO2 for sensitive ops)
export function requireAuthStrength(requiredStrength) {
  return (req, res, next) => {
    // This checks the Entra Conditional Access authentication context
    // In practice, Conditional Access enforces this before the token is issued
    // This is defense-in-depth
    if (requiredStrength === 'fido2' && req.identity.authStrength !== 'c1') {
      logAuditEvent({
        event_type: 'auth_strength_insufficient',
        user: req.identity.oid,
        required: requiredStrength,
        actual: req.identity.authStrength,
      });
      return res.status(403).json({ error: 'Phishing-resistant MFA required for this operation' });
    }
    next();
  };
}
