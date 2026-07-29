export interface DashboardSummary {
  total_hosts: number;
  live_hosts: number;
  open_ports: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  scans_completed: number;
  exploits_available: number;
}

export interface RiskDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface RecentScan {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  status: string;
  started_at: string;
  created_at: string;
}

export interface TopVulnerability {
  id: string;
  name: string;
  severity: string;
  cvss_score: number;
  host_count: number;
}
