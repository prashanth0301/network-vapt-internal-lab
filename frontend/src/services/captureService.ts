import apiClient from './api';

export interface PacketCapture {
  id: string;
  filename: string;
  size: string;
  packets: number;
  duration: string;
  date: string;
  status: string;
  protocol_stats: Record<string, number>;
  scan_id: string | null;
}

export interface ProtocolStat {
  protocol: string;
  percentage: number;
  packets: number;
}

export async function getCaptures(assessmentId?: string): Promise<PacketCapture[]> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  const res = await apiClient.get(`/captures?${params}`);
  return res.data?.data || [];
}

export async function getCaptureProtocols(assessmentId?: string): Promise<ProtocolStat[]> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  const res = await apiClient.get(`/captures/protocols?${params}`);
  return res.data?.data || [];
}

export async function uploadCapture(file: File, assessmentId?: string): Promise<{ data?: unknown; message: string }> {
  const form = new FormData();
  form.append('file', file);
  if (assessmentId) form.append('assessment_id', assessmentId);
  const res = await apiClient.post('/captures/upload', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return res.data;
}

export async function startLiveCapture(interfaceName: string, assessmentId?: string): Promise<{ data?: unknown; message: string }> {
  const params = new URLSearchParams();
  params.set('interface', interfaceName);
  if (assessmentId) params.set('assessment_id', assessmentId);
  const res = await apiClient.post('/captures/start', params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  return res.data;
}

export async function stopLiveCapture(captureId: string): Promise<{ data?: unknown; message: string }> {
  const params = new URLSearchParams();
  params.set('capture_id', captureId);
  const res = await apiClient.post('/captures/stop', params.toString(), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  return res.data;
}
