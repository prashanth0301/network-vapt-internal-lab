import type { ApiResponse, PaginatedResponse } from '../types/common';
import type { ServiceEnrichRequest, ServiceIntelligence } from '../types/service';
import apiClient from './api';

export async function getServices(
  category?: string,
  confidenceMin?: number,
  search?: string,
  sortBy = 'name',
  sortOrder = 'asc',
  page = 1,
  perPage = 20,
): Promise<PaginatedResponse<ServiceIntelligence>> {
  const params = new URLSearchParams();
  if (category) params.set('category', category);
  if (confidenceMin !== undefined) params.set('confidence_min', String(confidenceMin));
  if (search) params.set('search', search);
  params.set('sort_by', sortBy);
  params.set('sort_order', sortOrder);
  params.set('page', String(page));
  params.set('per_page', String(perPage));
  const response = await apiClient.get<PaginatedResponse<ServiceIntelligence>>(`/services?${params}`);
  return response.data;
}

export async function getServiceById(id: string): Promise<ApiResponse<ServiceIntelligence>> {
  const response = await apiClient.get<ApiResponse<ServiceIntelligence>>(`/services/${id}`);
  return response.data;
}

export async function getServicesByHost(hostId: string): Promise<ApiResponse<ServiceIntelligence[]>> {
  const response = await apiClient.get<ApiResponse<ServiceIntelligence[]>>(`/services/by-host/${hostId}`);
  return response.data;
}

export async function getServicesByAssessment(assessmentId: string): Promise<ApiResponse<ServiceIntelligence[]>> {
  const response = await apiClient.get<ApiResponse<ServiceIntelligence[]>>(`/services/by-assessment/${assessmentId}`);
  return response.data;
}

export async function getCategories(): Promise<ApiResponse<string[]>> {
  const response = await apiClient.get<ApiResponse<string[]>>('/services/categories');
  return response.data;
}

export async function enrichServices(request?: ServiceEnrichRequest): Promise<ApiResponse<{ services_enriched: number }>> {
  const response = await apiClient.post<ApiResponse<{ services_enriched: number }>>('/services/enrich', request || {});
  return response.data;
}
