export interface CVE {
  id: string;
  vuln_id: string | null;
  cve_id: string;
  description: string | null;
  cvss_v2: number | null;
  cvss_v3: number | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_severity: string | null;
  base_score: number | null;
  exploitability_score: number | null;
  impact_score: number | null;
  cwe_id: string | null;
  exploit_available: boolean | null;
  metasploit_module: string | null;
  reference_urls: string[] | null;
  published_date: string | null;
  last_modified: string | null;
  epss_score: number | null;
  kev_status: boolean | null;
  source: string | null;
  vendor: string | null;
  product: string | null;
  affected_versions: string[] | null;
  remediation_priority: string | null;
  created_at: string;
  updated_at: string;
}

export interface CVEStatistics {
  total_cves: number;
  severity_counts: Record<string, number>;
  kev_count: number;
  average_cvss: number;
  average_epss: number;
  top_vendors: { vendor: string; count: number }[];
}
