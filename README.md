# Locksmith

Zero Trust Credential Lifecycle - Token Substitution Proxy

## What is this

Locksmith is a credential proxy that ensures no engineer ever touches a plaintext credential. Clients authenticate via Entra ID, receive opaque nonce tokens, and make API calls through the proxy. The proxy swaps the nonce for the real credential, forwards the request, and returns the result. The nonce is worthless outside the proxy.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Claude Code │     │   Locksmith  │     │  Target API  │
│  / CLI / CI  │────>│    Proxy     │────>│  (Slack, AWS │
│              │     │   (EC2)      │     │   GitHub...) │
│ holds: nonce │     │ holds: real  │     │              │
│ (worthless)  │     │ credential   │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
       │                    │
       │ Entra ID           │ Secrets Manager
       │ OIDC token         │ 1Password Connect
       ▼                    ▼
┌──────────────┐     ┌──────────────┐
│  Entra ID    │     │  Credential  │
│  (Root of    │     │  Stores      │
│   Trust)     │     │              │
└──────────────┘     └──────────────┘
```

## Running locally

```bash
# Install deps
npm install

# Run with op run for secrets injection
op run --env-file .env.locksmith -- node src/index.js

# Or for dev (requires local Redis)
ENTRA_TENANT_ID=your-tenant-id \
ENTRA_CLIENT_ID=your-client-id \
npm run dev
```

## API

All authenticated routes require `Authorization: Bearer <entra-oidc-token>`.

### Nonce Management

```
POST /nonce              - Request a nonce for a service
DELETE /nonce             - Revoke all your active nonces
GET  /nonce/policy/:svc  - Get nonce policy for a service
```

### Proxy (Token Substitution)

```
ANY /proxy/:service/*    - Proxy request with nonce substitution
                           Header: X-Locksmith-Nonce: <nonce-id>
```

### Rotation

```
GET  /rotate             - List available rotation plugins
POST /rotate/:service    - Trigger credential rotation
```

### Health

```
GET /health              - Unauthenticated health check
GET /status              - Authenticated system status
```

## Nonce Types

| Type        | Behavior                                    |
|-------------|---------------------------------------------|
| single_use  | Consumed on first use, then deleted          |
| session     | Valid for TTL duration, reusable             |

## Security Model

- Real credentials NEVER leave the proxy EC2 instance
- Nonces are opaque UUIDs with zero cryptographic relationship to credentials
- Scope binding: nonces are validated against declared scope on every request
- Anomaly detection: per-user behavioral fingerprinting with escalation
- Audit: every nonce issuance, proxy request, and rotation is logged (credential fingerprints only, never values)

## License

Proprietary. All rights reserved.
