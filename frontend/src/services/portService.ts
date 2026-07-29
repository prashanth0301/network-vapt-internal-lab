import type { ApiResponse } from '../types/common';
import type { Port, PortScanRequest } from '../types/port';
import apiClient from './api';

export async function getPorts(
  state?: string,
  protocol?: string,
  page = 1,
  perPage = 20,
): Promise<ApiResponse<Port[]>> {
  const params = new URLSearchParams();
  if (state) params.set('state', state);
  if (protocol) params.set('protocol', protocol);
  params.set('page', String(page));
  params.set('per_page', String(perPage));
  const response = await apiClient.get<ApiResponse<Port[]>>(`/v1/ports?${params}`);
  return response.data;
}

export async function getPortById(id: string): Promise<ApiResponse<Port>> {
  const response = await apiClient.get<ApiResponse<Port>>(`/v1/ports/${id}`);
  return response.data;
}

export async function getPortsByHost(hostId: string): Promise<ApiResponse<Port[]>> {
  const response = await apiClient.get<ApiResponse<Port[]>>(`/v1/ports/by-host/${hostId}`);
  return response.data;
}

export async function getPortsByAssessment(assessmentId: string): Promise<ApiResponse<Port[]>> {
  const response = await apiClient.get<ApiResponse<Port[]>>(`/v1/ports/by-assessment/${assessmentId}`);
  return response.data;
}

export async function startPortScan(request: PortScanRequest): Promise<ApiResponse<{ assessment_id: string }>> {
  const response = await apiClient.post<ApiResponse<{ assessment_id: string }>>('/v1/ports/scan', request);
  return response.data;
}
