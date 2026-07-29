export interface Port {
  id: string;
  host_id: string;
  port: number;
  protocol: string;
  state: string;
  reason: string | null;
  created_at: string;
  updated_at: string;
  services: Service[];
}

export interface Service {
  id: string;
  port_id: string;
  name: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  tunnel: string | null;
  banner: string | null;
  created_at: string;
  updated_at: string;
}

export interface PortScanRequest {
  target: string;
  scan_type: 'tcp_syn' | 'tcp_connect' | 'udp_scan' | 'version_detection';
  scan_profile: 'top_ports' | 'custom_range' | 'all_ports';
  ports?: string;
  extra_args?: string[];
}
