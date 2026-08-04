import type { ApiResponse, PaginatedResponse } from '../types/common';
import type { AuditLog, AuditLogMeta, AuditLogQueryParams } from '../types/auth';
import apiClient from './api';

export async function getAuditLogsPaged(
  params: AuditLogQueryParams = {},
): Promise<PaginatedResponse<AuditLog>> {
  const query = new URLSearchParams();
  if (params.search) query.set('search', params.search);
  if (params.user) query.set('user', params.user);
  if (params.action) query.set('action', params.action);
  if (params.status) query.set('status', params.status);
  if (params.date_from) query.set('date_from', params.date_from);
  if (params.date_to) query.set('date_to', params.date_to);
  if (params.sort_by) query.set('sort_by', params.sort_by);
  if (params.sort_order) query.set('sort_order', params.sort_order);
  if (params.page) query.set('page', String(params.page));
  if (params.per_page) query.set('per_page', String(params.per_page));
  const response = await apiClient.get<PaginatedResponse<AuditLog>>(
    `/audit-logs?${query.toString()}`,
  );
  return response.data;
}

export async function getAuditLogMeta(): Promise<ApiResponse<AuditLogMeta>> {
  const response = await apiClient.get<ApiResponse<AuditLogMeta>>('/audit-logs/meta');
  return response.data;
}

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function buildExportQuery(params: AuditLogQueryParams): string {
  const query = new URLSearchParams();
  if (params.search) query.set('search', params.search);
  if (params.user) query.set('user', params.user);
  if (params.action) query.set('action', params.action);
  if (params.status) query.set('status', params.status);
  if (params.date_from) query.set('date_from', params.date_from);
  if (params.date_to) query.set('date_to', params.date_to);
  return query.toString();
}

function extractFilename(contentDisposition: string | undefined, format: 'csv' | 'json'): string {
  if (contentDisposition) {
    const match = /filename="?([^";]+)"?/.exec(contentDisposition);
    if (match) return match[1];
  }
  const stamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-');
  return `audit-logs-${stamp}.${format}`;
}

export async function exportAuditLogs(
  format: 'csv' | 'json',
  params: AuditLogQueryParams = {},
): Promise<void> {
  const query = buildExportQuery(params);
  const response = await apiClient.get(`/audit-logs/export?format=${format}&${query}`, {
    responseType: 'blob',
  });
  const blob = response.data as Blob;
  downloadBlob(blob, extractFilename(response.headers['content-disposition'], format));
}
