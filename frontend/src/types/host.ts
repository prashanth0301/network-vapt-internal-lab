export interface Host {
  id: string;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  vendor: string | null;
  os_name: string | null;
  os_version: string | null;
  os_accuracy: number | null;
  status: string;
  is_alive: boolean;
  latency: number | null;
  first_seen: string;
  last_seen: string;
}

export interface HostDiscoverRequest {
  target: string;
  scan_type: 'ping_sweep' | 'arp_scan' | 'quick_scan';
}

export interface PortInfo {
  id: string;
  port: number;
  protocol: string;
  state: string;
  reason: string | null;
  created_at: string;
}

export interface ServiceInfo {
  id: string;
  port: number;
  protocol: string;
  name: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  tunnel: string | null;
  category: string | null;
  confidence: number | null;
  normalized_name: string | null;
  banner: string | null;
}

export interface BannerInfo {
  id: string;
  port: number;
  protocol: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  banner: string;
}

export interface VulnerabilityInfo {
  id: string;
  name: string;
  severity: string | null;
  risk_score: number | null;
  cvss_vector: string | null;
  status: string | null;
  confidence: number | null;
  cve_ids: string[] | null;
  cve_count: number | null;
  created_at: string;
}

export interface CveInfo {
  id: string;
  vulnerability_id: string | null;
  cve_id: string;
  description: string | null;
  cvss_v3: number | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  exploit_available: boolean;
  metasploit_module: string | null;
  epss_score: number | null;
  kev_status: boolean;
  published_date: string | null;
  source: string | null;
  reference_urls: string[] | null;
}

export interface ExploitInfo {
  id: string;
  module_name: string | null;
  exploit_name: string | null;
  cve: string | null;
  rank: string | null;
  remote_local: string | null;
  provider: string;
  verified: boolean;
  status: string | null;
  risk_level: string | null;
  confidence: number | null;
  session_created: boolean;
  start_time: string | null;
  end_time: string | null;
  duration: number | null;
}

export interface EvidenceInfo {
  id: string;
  name: string;
  severity: string | null;
  evidence: string | null;
  plugin_output: string | null;
  raw_scanner_output: string | null;
  references: string[] | null;
  cve_ids: string[] | null;
  created_at: string;
}

export interface ScanHistoryInfo {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  created_at: string;
}

export interface ReportInfo {
  id: string;
  title: string;
  report_type: string;
  format: string;
  file_size: number | null;
  created_at: string;
}

export interface OSInformation {
  hostname: string | null;
  os_name: string | null;
  os_version: string | null;
  os_accuracy: number | null;
  vendor: string | null;
  mac_address: string | null;
  status: string;
  is_alive: boolean;
  latency: number | null;
  first_seen: string;
  last_seen: string;
}

export interface HostDetailsSummary {
  ports: number;
  open_ports: number;
  services: number;
  banners: number;
  vulnerabilities: number;
  cves: number;
  exploits: number;
  evidence: number;
  scans: number;
  reports: number;
}

export interface HostDetails {
  host: Host;
  os_information: OSInformation;
  open_ports: PortInfo[];
  services: ServiceInfo[];
  banners: BannerInfo[];
  vulnerabilities: VulnerabilityInfo[];
  cves: CveInfo[];
  exploits: ExploitInfo[];
  evidence: EvidenceInfo[];
  scan_history: ScanHistoryInfo[];
  reports: ReportInfo[];
  summary: HostDetailsSummary;
}
