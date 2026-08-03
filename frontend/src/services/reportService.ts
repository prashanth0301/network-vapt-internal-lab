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

export interface ReportListParams {
  assessmentId?: string;
  reportType?: string;
  search?: string;
  sortBy?: string;
  sortOrder?: string;
}

export async function getReports(params: ReportListParams = {}): Promise<Report[]> {
  const query = new URLSearchParams();
  if (params.assessmentId) query.set('assessment_id', params.assessmentId);
  if (params.reportType) query.set('report_type', params.reportType);
  if (params.search) query.set('search', params.search);
  if (params.sortBy) query.set('sort_by', params.sortBy);
  if (params.sortOrder) query.set('sort_order', params.sortOrder);
  const res = await apiClient.get(`/reports?${query.toString()}`);
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

export async function renameReport(id: string, title: string): Promise<Report> {
  const res = await apiClient.patch(`/reports/${id}`, null, {
    params: { title },
  });
  return res.data?.data as Report;
}

export async function deleteReport(id: string): Promise<{ message?: string }> {
  const res = await apiClient.delete(`/reports/${id}`);
  return res.data;
}
