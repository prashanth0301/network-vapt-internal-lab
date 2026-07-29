export interface Host {
  id: string;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  os_name: string | null;
  os_version: string | null;
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
