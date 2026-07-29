export interface Scan {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  started_at: string | null;
  completed_at: string | null;
  summary: Record<string, unknown> | null;
  error_message: string | null;
  created_at: string;
}

export interface ScanCreateRequest {
  name: string;
  scan_type: string;
  target: string;
  parameters?: Record<string, unknown>;
}
