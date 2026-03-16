/**
 * Shared type definitions for Locksmith.
 */

/** Identity attached to `req.identity` by the auth middleware. */
export interface Identity {
  sub: string;
  oid: string;
  name: string;
  email: string;
  groups: string[];
  deviceId: string | null;
  authStrength: string | null;
  tid: string;
}

/** Extend Express Request to carry the identity set by requireAuth. */
declare global {
  namespace Express {
    interface Request {
      identity: Identity;
    }
  }
}
