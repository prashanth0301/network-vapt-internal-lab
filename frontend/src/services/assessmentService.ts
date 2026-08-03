import type { ApiResponse } from '../types/common';
import type {
  Assessment,
  AssessmentCreateRequest,
  AssessmentListParams,
  AssessmentStatistics,
  AssessmentSummary,
} from '../types/assessment';
import apiClient from './api';

export async function createAssessment(request: AssessmentCreateRequest): Promise<ApiResponse<Assessment>> {
  const response = await apiClient.post<ApiResponse<Assessment>>('/assessments', request);
  return response.data;
}

export async function getAssessmentStatistics(): Promise<ApiResponse<AssessmentStatistics>> {
  const response = await apiClient.get<ApiResponse<AssessmentStatistics>>('/assessments/statistics');
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

export async function getAssessments(params: AssessmentListParams = {}): Promise<ApiResponse<Assessment[]>> {
  const query = new URLSearchParams();
  if (params.status) query.set('status', params.status);
  if (params.scanType) query.set('scan_type', params.scanType);
  if (params.search) query.set('search', params.search);
  if (params.target) query.set('target', params.target);
  if (params.dateFrom) query.set('date_from', params.dateFrom);
  if (params.dateTo) query.set('date_to', params.dateTo);
  query.set('page', String(params.page ?? 1));
  query.set('per_page', String(params.perPage ?? 100));
  const response = await apiClient.get<ApiResponse<Assessment[]>>(`/assessments?${query}`);
  return response.data;
}

export async function getAssessmentSummary(id: string): Promise<ApiResponse<AssessmentSummary>> {
  const response = await apiClient.get<ApiResponse<AssessmentSummary>>(`/assessments/${id}/summary`);
  return response.data;
}

export async function cloneAssessment(id: string): Promise<ApiResponse<Assessment>> {
  const response = await apiClient.post<ApiResponse<Assessment>>(`/assessments/${id}/clone`);
  return response.data;
}

export async function deleteAssessment(id: string): Promise<ApiResponse<{ deleted: boolean }>> {
  const response = await apiClient.delete<ApiResponse<{ deleted: boolean }>>(`/assessments/${id}`);
  return response.data;
}
