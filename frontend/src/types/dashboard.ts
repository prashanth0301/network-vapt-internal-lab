export interface SeveritySlice {
  severity: string;
  count: number;
}

export interface TrendPoint {
  date: string;
  count: number;
}

export interface PortSlice {
  port: number;
  count: number;
  label?: string | null;
}

export interface ServiceSlice {
  name: string;
  count: number;
}

export interface AssessmentItem {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  status: string;
  created_at: string | null;
}

export interface ReportItem {
  id: string;
  title: string;
  report_type: string;
  format: string;
  file_size: number | null;
  created_at: string | null;
}

export interface HostVulnItem {
  ip_address: string;
  hostname?: string | null;
  count: number;
}

export interface RiskScore {
  score: number;
  level: string;
  total: number;
}

export interface ScanDurationStats {
  count: number;
  average_seconds: number | null;
  min_seconds: number | null;
  max_seconds: number | null;
}

export interface ActivityItem {
  action: string;
  user: string;
  timestamp: string | null;
}

export interface DashboardTotals {
  vulnerabilities: number;
  hosts: number;
  open_ports: number;
  services: number;
  reports: number;
  assessments: number;
}

export interface DashboardSummary {
  severity_distribution: SeveritySlice[];
  vulnerability_trend: TrendPoint[];
  top_open_ports: PortSlice[];
  service_distribution: ServiceSlice[];
  recent_assessments: AssessmentItem[];
  recent_reports: ReportItem[];
  top_vulnerable_hosts: HostVulnItem[];
  risk_score: RiskScore;
  critical_count: number;
  exploit_available_count: number;
  scan_duration_stats: ScanDurationStats;
  activity_timeline: ActivityItem[];
  totals: DashboardTotals;
}
