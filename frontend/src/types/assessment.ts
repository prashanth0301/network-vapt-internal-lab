export interface AssessmentStage {
  stage_name: string;
  display_name: string;
  weight: number;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  summary: Record<string, unknown> | null;
}

export interface AssessmentProgress {
  overall_progress: number;
  total_weight: number;
  stages: AssessmentStage[];
  started_at: string | null;
  completed_at: string | null;
}

export interface AssessmentPipelineStage {
  name: string;
  display_name: string;
  description: string;
  weight: number;
  order: number;
  is_required: boolean;
  depends_on: string[];
}

export interface Assessment {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  status: 'draft' | 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  parameters: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  duration_seconds: number | null;
  progress_percent: number | null;
  severity_counts: Record<string, number> | null;
  progress: AssessmentProgress | null;
  pipeline: AssessmentPipelineStage[] | null;
}

export interface AssessmentSummary {
  id: string;
  name: string;
  scan_type: string;
  target: string;
  status: string;
  parameters: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  duration_seconds: number | null;
  progress_percent: number | null;
  progress: AssessmentProgress | null;
  pipeline: AssessmentPipelineStage[] | null;
  severity_counts: Record<string, number>;
  total_vulnerabilities: number;
  hosts_count: number;
  ports_count: number;
  services_count: number;
  reports_count: number;
  exploits_count: number;
  captures_count: number;
}

export interface AssessmentListParams {
  status?: string;
  scanType?: string;
  search?: string;
  target?: string;
  dateFrom?: string;
  dateTo?: string;
  page?: number;
  perPage?: number;
}

export interface AssessmentCreateRequest {
  name: string;
  scan_type: string;
  target: string;
  parameters?: Record<string, unknown>;
}

export interface AssessmentStatistics {
  total: number;
  by_status: Record<string, number>;
  success_count: number;
  failure_count: number;
  active_count: number;
}
