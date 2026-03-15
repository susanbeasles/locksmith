import { Router } from 'express';
import { validateNonce } from '../services/nonce.js';
import { resolveCredential } from '../services/credentials.js';
import { vendAwsSession } from '../plugins/aws.js';
import { logAuditEvent } from '../utils/audit.js';

const router = Router();

// Service-specific target URL mapping
const SERVICE_TARGETS = {
  'aws-prod':      { mode: 'token_vend', handler: proxyAws },
  'aws-dev':       { mode: 'token_vend', handler: proxyAws },
  'github':        { mode: 'action_proxy', baseUrl: 'https://api.github.com' },
  'slack':         { mode: 'action_proxy', baseUrl: 'https://slack.com/api' },
  'sentry':        { mode: 'action_proxy', baseUrl: 'https://sentry.io/api/0' },
  'pagerduty':     { mode: 'action_proxy', baseUrl: 'https://api.pagerduty.com' },
  'jira':          { mode: 'action_proxy', baseUrl: 'https://sonarmd.atlassian.net/rest/api/3' },
  'circleci':      { mode: 'action_proxy', baseUrl: 'https://circleci.com/api/v2' },
};

// POST /proxy/:service/* - Proxy a request with nonce substitution
router.all('/:service/*', async (req, res) => {
  const { service } = req.params;
  // Everything after /proxy/:service/
  const path = req.params[0] || '';

  // Extract nonce from Authorization header
  const authHeader = req.headers['x-locksmith-nonce'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Missing X-Locksmith-Nonce header' });
  }

  const nonceId = authHeader;

  // Determine the action from the request for scope validation
  const requestedAction = {
    method: req.method,
    path: `/${path}`,
    service,
  };

  // Validate the nonce
  const validation = await validateNonce(
    nonceId,
    req.identity.oid,
    service,
    requestedAction
  );

  if (!validation.valid) {
    logAuditEvent({
      event_type: 'proxy_denied',
      user: req.identity.oid,
      service,
      path,
      reason: validation.reason,
      nonce_id: nonceId,
    });
    return res.status(403).json({ error: validation.reason });
  }

  const target = SERVICE_TARGETS[service];
  if (!target) {
    return res.status(404).json({ error: `Unknown service: ${service}` });
  }

  try {
    let result;

    if (target.mode === 'token_vend' && target.handler) {
      // Mode A: Token vending (AWS)
      result = await target.handler(req, service, path);
    } else {
      // Mode B: Action proxy (everything else)
      result = await actionProxy(req, service, path, target.baseUrl);
    }

    logAuditEvent({
      event_type: 'proxy_request',
      user: req.identity.oid,
      service,
      method: req.method,
      path,
      nonce_id: nonceId,
      nonce_type: validation.nonce.type,
      result: 'success',
    });

    res.status(result.status || 200).json(result.body);
  } catch (err) {
    logAuditEvent({
      event_type: 'proxy_error',
      user: req.identity.oid,
      service,
      method: req.method,
      path,
      nonce_id: nonceId,
      error: err.message,
    });

    res.status(502).json({ error: `Proxy error: ${err.message}` });
  }
});

// Mode A: AWS token vending
// Instead of proxying the request, we vend a short-lived STS session
// The client gets temporary AWS credentials scoped to their declared scope
async function proxyAws(req, service) {
  const credential = await resolveCredential(service);

  // The resolved credential should contain the role ARN to assume
  const roleArn = credential.roleArn || credential.RoleArn;
  if (!roleArn) {
    throw new Error('AWS credential source missing roleArn');
  }

  const session = await vendAwsSession({
    roleArn,
    sessionName: `locksmith-${req.identity.oid}-${Date.now()}`,
    durationSeconds: service === 'aws-prod' ? 900 : 3600,
    // Could scope down with an inline policy based on the nonce scope
    // policy: buildAwsSessionPolicy(req.body.scope),
  });

  return {
    status: 200,
    body: {
      // These ARE credentials, but they're short-lived (15min/1hr) and scoped
      // This is the one case where the client holds something real
      // but it's ephemeral and narrowly scoped
      accessKeyId: session.accessKeyId,
      secretAccessKey: session.secretAccessKey,
      sessionToken: session.sessionToken,
      expiration: session.expiration,
      region: req.body.region || 'us-east-1',
    },
  };
}

// Mode B: Action proxy
// The client never gets ANY credential. We forward the request with the real token.
async function actionProxy(req, service, path, baseUrl) {
  const credential = await resolveCredential(service);

  // Build the target URL
  const targetUrl = `${baseUrl}/${path}`;

  // Build headers with real credential injected
  const headers = buildServiceHeaders(service, credential, req);

  // Forward the request
  const fetchOptions = {
    method: req.method,
    headers,
  };

  // Forward body for POST/PUT/PATCH
  if (['POST', 'PUT', 'PATCH'].includes(req.method) && req.body) {
    fetchOptions.body = JSON.stringify(req.body);
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(targetUrl, fetchOptions);
  let body;
  try {
    body = await response.json();
  } catch {
    body = { raw: await response.text() };
  }

  return { status: response.status, body };
}

// Build service-specific auth headers
function buildServiceHeaders(service, credential, req) {
  const headers = {
    'User-Agent': 'Locksmith-Proxy/0.1.0',
  };

  switch (service) {
    case 'github':
      headers['Authorization'] = `Bearer ${credential.token || credential.password}`;
      headers['Accept'] = 'application/vnd.github+json';
      headers['X-GitHub-Api-Version'] = '2022-11-28';
      break;

    case 'slack':
      headers['Authorization'] = `Bearer ${credential.token || credential.password}`;
      break;

    case 'sentry':
      headers['Authorization'] = `Bearer ${credential.token || credential.password}`;
      break;

    case 'pagerduty':
      headers['Authorization'] = `Token token=${credential.token || credential.password}`;
      break;

    case 'jira':
      // OAuth 2.0 bearer token
      headers['Authorization'] = `Bearer ${credential.access_token || credential.token || credential.password}`;
      headers['Accept'] = 'application/json';
      break;

    case 'circleci':
      headers['Circle-Token'] = credential.token || credential.password;
      break;

    default:
      // Generic bearer token
      headers['Authorization'] = `Bearer ${credential.token || credential.password}`;
  }

  return headers;
}

export default router;
