import type { ApiResponse } from '../types/common';
import type { Host, HostDiscoverRequest } from '../types/host';
import apiClient from './api';

export async function getHosts(assessmentId?: string): Promise<ApiResponse<Host[]>> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  const response = await apiClient.get<ApiResponse<Host[]>>(`/hosts?${params}`);
  return response.data;
}

export async function getHostById(id: string): Promise<ApiResponse<Host>> {
  const response = await apiClient.get<ApiResponse<Host>>(`/hosts/${id}`);
  return response.data;
}

export async function getHostSummary(assessmentId?: string): Promise<ApiResponse<{ total_hosts: number; alive_hosts: number }>> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  const response = await apiClient.get<ApiResponse<{ total_hosts: number; alive_hosts: number }>>(`/hosts/summary?${params}`);
  return response.data;
}

export async function startDiscovery(request: HostDiscoverRequest): Promise<ApiResponse<{ assessment_id: string }>> {
  const response = await apiClient.post<ApiResponse<{ assessment_id: string }>>('/hosts/discover', request);
  return response.data;
}

export async function deleteHost(id: string): Promise<ApiResponse<{ deleted: boolean }>> {
  const response = await apiClient.delete<ApiResponse<{ deleted: boolean }>>(`/hosts/${id}`);
  return response.data;
}
