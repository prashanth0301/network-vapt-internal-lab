export interface ServiceIntelligence {
  id: string;
  port_id: string;
  name: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  tunnel: string | null;
  protocol: string | null;
  banner: string | null;
  normalized_name: string | null;
  normalized_product: string | null;
  normalized_version: string | null;
  category: string | null;
  confidence: number | null;
  notes: string | null;
  created_at: string;
  updated_at: string;
  port_number: number | null;
  port_protocol: string | null;
  host_id: string | null;
  host_ip: string | null;
  host_name: string | null;
}

export interface ServiceEnrichRequest {
  service_ids?: string[];
}
