import type { ApiResponse } from '../types/common';
import type { Port, PortScanRequest } from '../types/port';
import apiClient from './api';

export async function getPorts(
  assessmentId?: string,
  state?: string,
  protocol?: string,
  page = 1,
  perPage = 20,
): Promise<ApiResponse<Port[]>> {
  const params = new URLSearchParams();
  if (state) params.set('state', state);
  if (protocol) params.set('protocol', protocol);
  if (assessmentId) params.set('assessment_id', assessmentId);
  params.set('page', String(page));
  params.set('per_page', String(perPage));
  const response = await apiClient.get<ApiResponse<Port[]>>(`/ports?${params}`);
  return response.data;
}

export async function getPortById(id: string): Promise<ApiResponse<Port>> {
  const response = await apiClient.get<ApiResponse<Port>>(`/ports/${id}`);
  return response.data;
}

export async function getPortsByHost(hostId: string): Promise<ApiResponse<Port[]>> {
  const response = await apiClient.get<ApiResponse<Port[]>>(`/ports/by-host/${hostId}`);
  return response.data;
}

export async function getPortsByAssessment(assessmentId: string): Promise<ApiResponse<Port[]>> {
  const response = await apiClient.get<ApiResponse<Port[]>>(`/ports/by-assessment/${assessmentId}`);
  return response.data;
}

export async function startPortScan(request: PortScanRequest): Promise<ApiResponse<{ assessment_id: string }>> {
  const response = await apiClient.post<ApiResponse<{ assessment_id: string }>>('/ports/scan', request);
  return response.data;
}
