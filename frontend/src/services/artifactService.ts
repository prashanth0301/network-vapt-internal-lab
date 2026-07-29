import apiClient from './api';
import type { ArtifactContent, ArtifactListResponse } from '../types/artifact';

export async function getArtifacts(
  assessmentId?: string,
  stageName?: string,
  page = 1,
  perPage = 20,
  sortBy = 'created_at',
  sortOrder = 'desc',
): Promise<ArtifactListResponse> {
  const params: Record<string, string | number> = { page, per_page: perPage, sort_by: sortBy, sort_order: sortOrder };
  if (assessmentId) params.assessment_id = assessmentId;
  if (stageName) params.stage_name = stageName;
  const res = await apiClient.get('/artifacts', { params });
  return res.data;
}

export async function getArtifact(id: string) {
  const res = await apiClient.get(`/artifacts/${id}`);
  return res.data;
}

export async function getArtifactFiles(id: string) {
  const res = await apiClient.get(`/artifacts/${id}/files`);
  return res.data;
}

export async function downloadArtifactFile(id: string, filename: string): Promise<ArtifactContent> {
  const res = await apiClient.get(`/artifacts/${id}/download/${filename}`);
  return res.data;
}
