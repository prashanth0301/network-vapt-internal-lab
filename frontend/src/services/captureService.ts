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
  total_bytes: number;
  avg_packet_size: number;
  packets_per_second: number;
  scan_id: string | null;
  conversation_count?: number;
  started_at?: string | null;
  ended_at?: string | null;
}

export interface ProtocolStat {
  protocol: string;
  percentage: number;
  packets: number;
}

export interface CapturePacket {
  id: string;
  seq: number;
  timestamp: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  info: string | null;
}

export interface CaptureConversation {
  id: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  packets: number;
  bytes: number;
}

export interface CapturePacketsPage {
  items: CapturePacket[];
  total: number;
  page: number;
  per_page: number;
}

export interface CaptureInterface {
  id: string;
  name: string;
  description: string;
  ip_address?: string | null;
  mac_address?: string | null;
  status?: string | null;
}

export interface CaptureStatus {
  status: string;
  packets: number;
  bytes: number;
  duration_seconds: number;
  started_at?: string | null;
  interface?: string | null;
}

export async function getCaptures(assessmentId?: string, search?: string): Promise<PacketCapture[]> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  if (search) params.set('search', search);
  const res = await apiClient.get(`/captures?${params}`);
  return res.data?.data || [];
}

export async function getCaptureProtocols(assessmentId?: string): Promise<ProtocolStat[]> {
  const params = new URLSearchParams();
  if (assessmentId) params.set('assessment_id', assessmentId);
  const res = await apiClient.get(`/captures/protocols?${params}`);
  return res.data?.data || [];
}

export async function getCapture(id: string): Promise<PacketCapture | null> {
  const res = await apiClient.get(`/captures/${id}`);
  return res.data?.data || null;
}

export async function getCapturePackets(
  id: string,
  page = 1,
  perPage = 50,
  protocol?: string,
): Promise<CapturePacketsPage> {
  const params = new URLSearchParams();
  params.set('page', String(page));
  params.set('per_page', String(perPage));
  if (protocol) params.set('protocol', protocol);
  const res = await apiClient.get(`/captures/${id}/packets?${params}`);
  return (
    res.data?.data || { items: [], total: 0, page, per_page: perPage }
  );
}

export async function getCaptureConversations(id: string): Promise<CaptureConversation[]> {
  const res = await apiClient.get(`/captures/${id}/conversations`);
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

export async function getCaptureInterfaces(): Promise<CaptureInterface[]> {
  const res = await apiClient.get('/captures/interfaces');
  return res.data?.data || [];
}

export async function getCaptureStatus(id: string): Promise<CaptureStatus | null> {
  const res = await apiClient.get(`/captures/${id}/status`);
  return res.data?.data || null;
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

export async function downloadCapture(captureId: string, filename: string): Promise<void> {
  const res = await apiClient.get(`/captures/${captureId}/download`, { responseType: 'blob' });
  const url = window.URL.createObjectURL(res.data as Blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename || `capture_${captureId}.pcap`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export async function deleteCapture(captureId: string): Promise<{ message: string }> {
  const res = await apiClient.delete(`/captures/${captureId}`);
  return res.data;
}
