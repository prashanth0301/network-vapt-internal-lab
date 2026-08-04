import type { ApiResponse } from '../types/common';
import type { DashboardSummary } from '../types/dashboard';
import apiClient from './api';

export async function getDashboardSummary(assessmentId?: string): Promise<ApiResponse<DashboardSummary>> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  const qs = params.toString();
  const response = await apiClient.get<ApiResponse<DashboardSummary>>(`/dashboard/summary${qs ? `?${qs}` : ''}`);
  return response.data;
}
