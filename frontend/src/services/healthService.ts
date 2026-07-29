import type { HealthResponse } from '../types/health';
import apiClient from './api';

export async function checkHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>('/health');
  return response.data;
}
