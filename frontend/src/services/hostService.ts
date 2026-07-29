import type { ApiResponse } from '../types/common';
import type { Host, HostDiscoverRequest } from '../types/host';
import apiClient from './api';

export async function getHosts(): Promise<ApiResponse<Host[]>> {
  const response = await apiClient.get<ApiResponse<Host[]>>('/v1/hosts');
  return response.data;
}

export async function getHostById(id: string): Promise<ApiResponse<Host>> {
  const response = await apiClient.get<ApiResponse<Host>>(`/v1/hosts/${id}`);
  return response.data;
}

export async function getHostSummary(): Promise<ApiResponse<{ total_hosts: number; alive_hosts: number }>> {
  const response = await apiClient.get<ApiResponse<{ total_hosts: number; alive_hosts: number }>>('/v1/hosts/summary');
  return response.data;
}

export async function startDiscovery(request: HostDiscoverRequest): Promise<ApiResponse<{ assessment_id: string }>> {
  const response = await apiClient.post<ApiResponse<{ assessment_id: string }>>('/v1/hosts/discover', request);
  return response.data;
}

export async function deleteHost(id: string): Promise<ApiResponse<{ deleted: boolean }>> {
  const response = await apiClient.delete<ApiResponse<{ deleted: boolean }>>(`/v1/hosts/${id}`);
  return response.data;
}
