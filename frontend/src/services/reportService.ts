import apiClient from './api';

export interface Report {
  id: string;
  title: string;
  type: string;
  format: string;
  size: string;
  date: string;
  status: string;
  filepath: string;
  assessment_id: string | null;
}

export async function getReports(assessmentId?: string): Promise<Report[]> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  const res = await apiClient.get(`/reports?${params}`);
  return res.data?.data || [];
}

export async function generateReport(
  reportType: string,
  outputFormat: string,
  assessmentId?: string,
): Promise<{ data?: unknown; message: string }> {
  const params = new URLSearchParams();
  params.set('report_type', reportType);
  params.set('output_format', outputFormat);
  if (assessmentId) params.set('assessment_id', assessmentId);
  const res = await apiClient.post('/reports/generate', null, { params });
  return res.data;
}

export async function downloadReport(id: string): Promise<Blob> {
  const res = await apiClient.get(`/reports/download/${id}`, { responseType: 'blob' });
  return res.data as Blob;
}
