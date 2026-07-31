import apiClient from './api';

export interface SettingItem {
  key: string;
  value: string;
  category: string;
  description: string;
}

export async function getSettings(category?: string): Promise<SettingItem[]> {
  const params = new URLSearchParams();
  if (category) params.set('category', category);
  const res = await apiClient.get(`/settings?${params}`);
  return res.data?.data || [];
}

export async function saveSettings(values: Record<string, string>): Promise<{ message: string }> {
  const res = await apiClient.put('/settings', { values });
  return res.data;
}

export async function resetSettings(): Promise<{ message: string }> {
  const res = await apiClient.post('/settings/reset');
  return res.data;
}
