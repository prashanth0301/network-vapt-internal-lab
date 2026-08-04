export const SCAN_TYPE_LABELS: Record<string, string> = {
  full_assessment: 'Full Assessment',
  host_discovery: 'Host Discovery',
  port_scan: 'Port Scan',
  service_enum: 'Service Intelligence',
  vuln_scan: 'Vulnerability Scan',
};

export const STAGE_LABELS: Record<string, string> = {
  host_discovery: 'Host Discovery',
  port_scan: 'Port Scan',
  service_intelligence: 'Service Intelligence',
  vulnerability_assessment: 'Vulnerability Assessment',
  cve_intelligence: 'CVE Intelligence',
  exploit_verification: 'Exploit Verification',
};

export const SEVERITY_HEX: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  Info: '#3b82f6',
};

export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 10,
  high: 7,
  medium: 4,
  low: 1,
  info: 0,
};

export function statusColor(status: string): 'success' | 'warning' | 'danger' | 'info' | 'default' {
  switch (status) {
    case 'completed': return 'success';
    case 'failed': return 'danger';
    case 'running': return 'info';
    case 'cancelled': return 'warning';
    case 'pending': return 'warning';
    default: return 'default';
  }
}

export function formatSeconds(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  if (mins < 60) return `${mins}m ${secs}s`;
  const hours = Math.floor(mins / 60);
  return `${hours}h ${mins % 60}m`;
}

export function formatDuration(
  startedAt: string | null,
  completedAt: string | null,
  durationSeconds: number | null,
): string {
  if (durationSeconds !== null && durationSeconds > 0) {
    return formatSeconds(durationSeconds);
  }
  if (!startedAt || !completedAt) return '-';
  const seconds = (new Date(completedAt).getTime() - new Date(startedAt).getTime()) / 1000;
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs.toFixed(0)}s`;
}

export function progressColor(status: string): 'primary' | 'success' | 'warning' | 'danger' {
  if (status === 'completed') return 'success';
  if (status === 'failed') return 'danger';
  if (status === 'running') return 'primary';
  return 'warning';
}

/**
 * Risk score computed from severity counts, mirroring the dashboard's
 * weighted formula (see backend app/services/dashboard_service.py).
 */
export function computeRiskScore(counts: Record<string, number>): {
  score: number;
  level: string;
  total: number;
} {
  const total = Object.values(counts || {}).reduce((sum, n) => sum + n, 0);
  if (total === 0) return { score: 0, level: 'None', total: 0 };
  const weighted = Object.entries(counts).reduce(
    (sum, [severity, count]) => sum + (SEVERITY_WEIGHTS[severity.toLowerCase()] ?? 0) * count,
    0,
  );
  const score = Math.round((weighted / (10 * total)) * 100);
  const level =
    score >= 70 ? 'Critical' : score >= 45 ? 'High' : score >= 20 ? 'Medium' : score > 0 ? 'Low' : 'None';
  return { score, level, total };
}
