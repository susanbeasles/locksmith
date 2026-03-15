import { logAuditEvent } from '../utils/audit.js';
import { revokeAllNonces } from './nonce.js';

// Per-user access history (in-memory for Phase 1, Redis/DB for production)
const userHistory = new Map();

const WINDOW_MS = 60_000; // 1 minute sliding window
const MAX_NONCES_PER_WINDOW = 10;

// Record an access event and check for anomalies
export async function checkAnomaly({ userId, service, scope, accessMethod, deviceId, ip }) {
  const now = Date.now();

  // Get or initialize user history
  if (!userHistory.has(userId)) {
    userHistory.set(userId, {
      events: [],
      knownDevices: new Set(),
      knownMethods: new Set(),
      typicalServices: new Map(), // service -> count
    });
  }

  const history = userHistory.get(userId);

  // Add current event
  history.events.push({ timestamp: now, service, scope, accessMethod, deviceId, ip });

  // Prune events older than 10 minutes (keep enough for pattern analysis)
  history.events = history.events.filter(e => now - e.timestamp < 600_000);

  // Update known patterns
  if (deviceId) history.knownDevices.add(deviceId);
  if (accessMethod) history.knownMethods.add(accessMethod);
  history.typicalServices.set(service, (history.typicalServices.get(service) || 0) + 1);

  // Run heuristic checks
  const anomalies = [];

  // Check 1: Rapid nonce requests (>MAX in window)
  const recentEvents = history.events.filter(e => now - e.timestamp < WINDOW_MS);
  if (recentEvents.length > MAX_NONCES_PER_WINDOW) {
    anomalies.push({
      rule: 'rapid_access',
      severity: 'high',
      detail: `${recentEvents.length} requests in ${WINDOW_MS / 1000}s (threshold: ${MAX_NONCES_PER_WINDOW})`,
    });
  }

  // Check 2: Unknown device
  if (deviceId && history.knownDevices.size > 1 && !history.knownDevices.has(deviceId)) {
    // Only flag if we've seen this user before on other devices
    anomalies.push({
      rule: 'unknown_device',
      severity: 'medium',
      detail: `Access from unrecognized device: ${deviceId}`,
    });
  }

  // Check 3: Non-proxy access method (the big one)
  // If access is NOT through op run, Connect Server, or the proxy, it's suspicious
  const sanctionedMethods = ['proxy', 'op_run', 'connect_server', 'mcp_tool'];
  if (accessMethod && !sanctionedMethods.includes(accessMethod)) {
    anomalies.push({
      rule: 'unsanctioned_access_method',
      severity: 'high',
      detail: `Access via ${accessMethod} (sanctioned: ${sanctionedMethods.join(', ')})`,
    });
  }

  // Check 4: Unusual service access (first time accessing a high-value service)
  const highValueServices = ['aws-prod', 'postgres', 'mongodb-atlas'];
  if (highValueServices.includes(service) && (history.typicalServices.get(service) || 0) <= 1) {
    anomalies.push({
      rule: 'first_access_high_value',
      severity: 'low',
      detail: `First access to high-value service: ${service}`,
    });
  }

  // Check 5: Wildcard scope request
  if (scope === '*' || (typeof scope === 'object' && Object.values(scope).includes('*'))) {
    anomalies.push({
      rule: 'wildcard_scope',
      severity: 'medium',
      detail: 'Wildcard scope requested',
    });
  }

  // Process anomalies
  if (anomalies.length > 0) {
    const maxSeverity = anomalies.reduce((max, a) => {
      const order = { low: 0, medium: 1, high: 2 };
      return order[a.severity] > order[max] ? a.severity : max;
    }, 'low');

    logAuditEvent({
      event_type: 'anomaly_detected',
      user: userId,
      service,
      anomalies,
      max_severity: maxSeverity,
      action_taken: maxSeverity === 'high' ? 'nonces_revoked' : 'alert_only',
    });

    // High severity: revoke all nonces, force re-auth
    if (maxSeverity === 'high') {
      const revoked = await revokeAllNonces(userId);
      return {
        anomalous: true,
        severity: maxSeverity,
        anomalies,
        action: 'nonces_revoked',
        revoked,
      };
    }

    return {
      anomalous: true,
      severity: maxSeverity,
      anomalies,
      action: 'alert_only',
    };
  }

  return { anomalous: false };
}
