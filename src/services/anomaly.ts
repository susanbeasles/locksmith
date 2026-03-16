import { logAuditEvent } from '../utils/audit.js';
import { revokeAllNonces } from './nonce.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Severity = 'low' | 'medium' | 'high';

interface AnomalyFlag {
  rule: string;
  severity: Severity;
  detail: string;
}

interface AccessEvent {
  timestamp: number;
  service: string;
  scope: string | Record<string, string>;
  accessMethod: string;
  deviceId: string | undefined;
  ip: string | undefined;
}

interface UserHistory {
  events: AccessEvent[];
  knownDevices: Set<string>;
  knownMethods: Set<string>;
  typicalServices: Map<string, number>;
}

interface CheckAnomalyParams {
  userId: string;
  service: string;
  scope: string | Record<string, string>;
  accessMethod: string;
  deviceId?: string;
  ip?: string;
}

interface AnomalyResult {
  anomalous: boolean;
  severity?: Severity;
  anomalies?: AnomalyFlag[];
  action?: 'nonces_revoked' | 'alert_only';
  revoked?: number;
}

// ---------------------------------------------------------------------------
// Per-user access history (in-memory for Phase 1)
// ---------------------------------------------------------------------------

const userHistory = new Map<string, UserHistory>();

const WINDOW_MS = 60_000; // 1 minute sliding window
const MAX_NONCES_PER_WINDOW = 10;
const HISTORY_RETENTION_MS = 600_000; // 10 minutes

const SANCTIONED_METHODS: readonly string[] = [
  'proxy',
  'op_run',
  'connect_server',
  'mcp_tool',
] as const;

const HIGH_VALUE_SERVICES: readonly string[] = [
  'aws-prod',
  'postgres',
  'mongodb-atlas',
] as const;

const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

// ---------------------------------------------------------------------------
// Record an access event and check for anomalies
// ---------------------------------------------------------------------------

export async function checkAnomaly({
  userId,
  service,
  scope,
  accessMethod,
  deviceId,
  ip,
}: CheckAnomalyParams): Promise<AnomalyResult> {
  const now = Date.now();

  // Get or initialize user history
  if (!userHistory.has(userId)) {
    userHistory.set(userId, {
      events: [],
      knownDevices: new Set(),
      knownMethods: new Set(),
      typicalServices: new Map(),
    });
  }

  // Non-null assertion is safe because we just ensured the key exists
  const history = userHistory.get(userId)!;

  // Add current event
  history.events.push({ timestamp: now, service, scope, accessMethod, deviceId, ip });

  // Prune events older than retention window
  history.events = history.events.filter((e) => now - e.timestamp < HISTORY_RETENTION_MS);

  // Update known patterns
  if (deviceId) history.knownDevices.add(deviceId);
  if (accessMethod) history.knownMethods.add(accessMethod);
  history.typicalServices.set(service, (history.typicalServices.get(service) ?? 0) + 1);

  // Run heuristic checks
  const anomalies: AnomalyFlag[] = [];

  // Check 1: Rapid nonce requests (>MAX in window)
  const recentEvents = history.events.filter((e) => now - e.timestamp < WINDOW_MS);
  if (recentEvents.length > MAX_NONCES_PER_WINDOW) {
    anomalies.push({
      rule: 'rapid_access',
      severity: 'high',
      detail: `${recentEvents.length} requests in ${WINDOW_MS / 1000}s (threshold: ${MAX_NONCES_PER_WINDOW})`,
    });
  }

  // Check 2: Unknown device
  if (deviceId && history.knownDevices.size > 1 && !history.knownDevices.has(deviceId)) {
    anomalies.push({
      rule: 'unknown_device',
      severity: 'medium',
      detail: `Access from unrecognized device: ${deviceId}`,
    });
  }

  // Check 3: Non-proxy access method
  if (accessMethod && !SANCTIONED_METHODS.includes(accessMethod)) {
    anomalies.push({
      rule: 'unsanctioned_access_method',
      severity: 'high',
      detail: `Access via ${accessMethod} (sanctioned: ${SANCTIONED_METHODS.join(', ')})`,
    });
  }

  // Check 4: Unusual service access (first time accessing a high-value service)
  if (
    HIGH_VALUE_SERVICES.includes(service) &&
    (history.typicalServices.get(service) ?? 0) <= 1
  ) {
    anomalies.push({
      rule: 'first_access_high_value',
      severity: 'low',
      detail: `First access to high-value service: ${service}`,
    });
  }

  // Check 5: Wildcard scope request
  if (
    scope === '*' ||
    (typeof scope === 'object' && Object.values(scope).includes('*'))
  ) {
    anomalies.push({
      rule: 'wildcard_scope',
      severity: 'medium',
      detail: 'Wildcard scope requested',
    });
  }

  // Process anomalies
  if (anomalies.length > 0) {
    const maxSeverity = anomalies.reduce<Severity>((max, a) => {
      return SEVERITY_ORDER[a.severity] > SEVERITY_ORDER[max] ? a.severity : max;
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
