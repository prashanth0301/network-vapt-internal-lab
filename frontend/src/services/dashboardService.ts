import type { ApiResponse } from '../types/common';
import type { DashboardSummary } from '../types/dashboard';
import apiClient from './api';

export async function getDashboardSummary(): Promise<ApiResponse<DashboardSummary>> {
  const response = await apiClient.get<ApiResponse<DashboardSummary>>('/dashboard/summary');
  return response.data;
}
