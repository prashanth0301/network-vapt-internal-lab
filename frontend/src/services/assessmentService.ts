import type { ApiResponse } from '../types/common';
import type { Assessment, AssessmentCreateRequest } from '../types/assessment';
import apiClient from './api';

export async function createAssessment(request: AssessmentCreateRequest): Promise<ApiResponse<Assessment>> {
  const response = await apiClient.post<ApiResponse<Assessment>>('/assessments', request);
  return response.data;
}

export async function startAssessment(id: string): Promise<ApiResponse<Assessment>> {
  const response = await apiClient.post<ApiResponse<Assessment>>(`/assessments/${id}/start`);
  return response.data;
}

export async function getAssessment(id: string): Promise<ApiResponse<Assessment>> {
  const response = await apiClient.get<ApiResponse<Assessment>>(`/assessments/${id}`);
  return response.data;
}

export async function getAssessments(
  status?: string,
  scanType?: string,
  page = 1,
  perPage = 20,
): Promise<ApiResponse<Assessment[]>> {
  const params = new URLSearchParams();
  if (status) params.set('status', status);
  if (scanType) params.set('scan_type', scanType);
  params.set('page', String(page));
  params.set('per_page', String(perPage));
  const response = await apiClient.get<ApiResponse<Assessment[]>>(`/assessments?${params}`);
  return response.data;
}

export async function deleteAssessment(id: string): Promise<ApiResponse<{ deleted: boolean }>> {
  const response = await apiClient.delete<ApiResponse<{ deleted: boolean }>>(`/assessments/${id}`);
  return response.data;
}
