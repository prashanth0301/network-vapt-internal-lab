export interface Artifact {
  id: string;
  assessment_id: string;
  stage_name: string;
  scanner_name: string | null;
  command: string | null;
  parameters: Record<string, unknown> | null;
  scanner_version: string | null;
  target: string | null;
  start_time: string | null;
  end_time: string | null;
  duration: number | null;
  status: string;
  error_message: string | null;
  artifact_path: string;
  output_type: string | null;
  hash: string | null;
  created_at: string;
  updated_at: string;
}

export interface ArtifactListResponse {
  data: Artifact[];
  pagination: {
    page: number;
    per_page: number;
    total: number;
    total_pages: number;
  };
}

export interface ArtifactFile {
  filename: string;
  size: number;
  modified_at: string;
}

export interface ArtifactContent {
  id: string;
  stage_name: string;
  content_type: string;
  content: string;
  filename: string;
}
