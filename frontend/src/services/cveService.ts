import type { ApiResponse, PaginatedResponse } from '../types/common';
import type { CVE, CVEStatistics } from '../types/cve';
import apiClient from './api';

export async function getCVEs(
  severity?: string,
  vendor?: string,
  product?: string,
  year?: number,
  search?: string,
  kevOnly = false,
  sortBy = 'cvss_score',
  sortOrder = 'desc',
  page = 1,
  perPage = 20,
  assessmentId?: string,
): Promise<PaginatedResponse<CVE>> {
  const params = new URLSearchParams();
  if (severity) params.set('severity', severity);
  if (vendor) params.set('vendor', vendor);
  if (product) params.set('product', product);
  if (year) params.set('year', String(year));
  if (search) params.set('search', search);
  if (kevOnly) params.set('kev_only', 'true');
  if (assessmentId) params.set('assessment_id', assessmentId);
  params.set('sort_by', sortBy);
  params.set('sort_order', sortOrder);
  params.set('page', String(page));
  params.set('per_page', String(perPage));
  const response = await apiClient.get<PaginatedResponse<CVE>>(`/cves?${params}`);
  return response.data;
}

export async function getCVEById(id: string): Promise<ApiResponse<CVE>> {
  const response = await apiClient.get<ApiResponse<CVE>>(`/cves/${id}`);
  return response.data;
}

export async function searchCVEs(q: string): Promise<ApiResponse<CVE[]>> {
  const response = await apiClient.get<ApiResponse<CVE[]>>(`/cves/search?q=${encodeURIComponent(q)}`);
  return response.data;
}

export async function getCVEsByVulnerability(vulnId: string): Promise<ApiResponse<CVE[]>> {
  const response = await apiClient.get<ApiResponse<CVE[]>>(`/cves/by-vulnerability/${vulnId}`);
  return response.data;
}

export async function getHighRiskCVEs(limit = 20, assessmentId?: string): Promise<ApiResponse<CVE[]>> {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  if (assessmentId) params.set('assessment_id', assessmentId);
  const response = await apiClient.get<ApiResponse<CVE[]>>(`/cves/high-risk?${params}`);
  return response.data;
}

export async function getCVEStatistics(assessmentId?: string): Promise<ApiResponse<CVEStatistics>> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  const response = await apiClient.get<ApiResponse<CVEStatistics>>(`/cves/statistics?${params}`);
  return response.data;
}
