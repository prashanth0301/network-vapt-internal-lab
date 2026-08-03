import type { ApiResponse } from '../types/common';
import type { SettingItem, SystemInfo } from '../types/settings';
import apiClient from './api';

export async function getSettings(category?: string): Promise<ApiResponse<SettingItem[]>> {
  const params = new URLSearchParams();
  if (category) params.set('category', category);
  const response = await apiClient.get<ApiResponse<SettingItem[]>>(
    `/settings${params.toString() ? `?${params.toString()}` : ''}`,
  );
  return response.data;
}

export async function saveSettings(
  values: Record<string, string>,
): Promise<ApiResponse<{ updated: number }>> {
  const response = await apiClient.put<ApiResponse<{ updated: number }>>('/settings', {
    values,
  });
  return response.data;
}

export async function resetSettings(): Promise<ApiResponse<{ reset: boolean }>> {
  const response = await apiClient.post<ApiResponse<{ reset: boolean }>>('/settings/reset');
  return response.data;
}

export async function getSystemInfo(): Promise<ApiResponse<SystemInfo>> {
  const response = await apiClient.get<ApiResponse<SystemInfo>>('/settings/system');
  return response.data;
}

export async function uploadLogo(file: File): Promise<ApiResponse<{ filename: string }>> {
  const form = new FormData();
  form.append('file', file);
  const response = await apiClient.post<ApiResponse<{ filename: string }>>('/settings/logo', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
}

export async function removeLogo(): Promise<ApiResponse<{ removed: boolean }>> {
  const response = await apiClient.delete<ApiResponse<{ removed: boolean }>>('/settings/logo');
  return response.data;
}

/** Fetch the uploaded logo as a blob; returns an object URL or null when absent. */
export async function fetchLogoUrl(): Promise<string | null> {
  try {
    const response = await apiClient.get('/settings/logo', { responseType: 'blob' });
    if (response.status !== 200) return null;
    return URL.createObjectURL(response.data as Blob);
  } catch {
    return null;
  }
}
