import { useCallback, useEffect, useRef, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { getApiError } from '../services/api';
import {
  getCapture,
  getCaptureConversations,
  getCaptureInterfaces,
  getCapturePackets,
  getCaptureProtocols,
  getCaptureStatus,
  getCaptures,
  startLiveCapture,
  stopLiveCapture,
  uploadCapture,
  type CaptureConversation,
  type CaptureInterface,
  type CapturePacket,
  type CaptureStatus,
  type PacketCapture,
  type ProtocolStat,
} from '../services/captureService';
import { getActiveAssessmentId, useAssessmentChangeTick } from '../services/assessmentStore';

const PACKET_PAGE_SIZE = 50;

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  for (const unit of ['B', 'KB', 'MB', 'GB']) {
    if (bytes < 1024) return `${bytes.toFixed(1)} ${unit}`;
    bytes /= 1024;
  }
  return `${bytes.toFixed(1)} TB`;
}

function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
}

export function Packets() {
  const [captures, setCaptures] = useState<PacketCapture[]>([]);
  const [protocolStats, setProtocolStats] = useState<ProtocolStat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [activeCaptureId, setActiveCaptureId] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);

  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [interfacesError, setInterfacesError] = useState<string | null>(null);
  const [selectedInterface, setSelectedInterface] = useState('auto');
  const [liveStatus, setLiveStatus] = useState<CaptureStatus | null>(null);
  const [elapsed, setElapsed] = useState(0);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [captureDetail, setCaptureDetail] = useState<PacketCapture | null>(null);
  const [conversations, setConversations] = useState<CaptureConversation[]>([]);
  const [packets, setPackets] = useState<CapturePacket[]>([]);
  const [packetsTotal, setPacketsTotal] = useState(0);
  const [packetsPage, setPacketsPage] = useState(1);
  const [packetProtocol, setPacketProtocol] = useState('');
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const tick = useAssessmentChangeTick();
  const [refreshTick, setRefreshTick] = useState(0);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const [capList, protoList] = await Promise.all([
        getCaptures(assessmentId),
        getCaptureProtocols(assessmentId),
      ]);
      setCaptures(capList);
      setProtocolStats(protoList);
      const live = capList.find((c) => c.status === 'capturing');
      setCapturing(!!live);
      setActiveCaptureId(live ? live.id : null);
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  }, [tick]);

  useEffect(() => { fetchData(); }, [fetchData]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const list = await getCaptureInterfaces();
        if (!cancelled) {
          setInterfaces(list);
          setInterfacesError(null);
        }
      } catch (e) {
        if (!cancelled) setInterfacesError(getApiError(e));
      }
    })();
    return () => { cancelled = true; };
  }, [tick]);

  // Live status polling while a capture is active (packet count, bytes).
  useEffect(() => {
    if (!capturing || !activeCaptureId) {
      setLiveStatus(null);
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const status = await getCaptureStatus(activeCaptureId);
        if (!cancelled && status) setLiveStatus(status);
      } catch {
        /* transient polling failure - ignore */
      }
    };
    poll();
    const timer = window.setInterval(poll, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [capturing, activeCaptureId]);

  // Duration ticker while a capture is active.
  useEffect(() => {
    if (!capturing) {
      setElapsed(0);
      return;
    }
    const timer = window.setInterval(() => {
      setElapsed((e) => e + 1);
    }, 1000);
    return () => window.clearInterval(timer);
  }, [capturing]);

  useEffect(() => {
    if (!selectedId) {
      setCaptureDetail(null);
      setConversations([]);
      setPackets([]);
      setPacketsTotal(0);
      return;
    }
    let cancelled = false;
    setDetailLoading(true);
    setDetailError(null);
    (async () => {
      try {
        const [detail, convList, packetPage] = await Promise.all([
          getCapture(selectedId),
          getCaptureConversations(selectedId),
          getCapturePackets(selectedId, packetsPage, PACKET_PAGE_SIZE, packetProtocol || undefined),
        ]);
        if (cancelled) return;
        setCaptureDetail(detail);
        setConversations(convList);
        setPackets(packetPage.items);
        setPacketsTotal(packetPage.total);
      } catch (e) {
        if (!cancelled) setDetailError(getApiError(e));
      } finally {
        if (!cancelled) setDetailLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [selectedId, packetsPage, packetProtocol, refreshTick]);

  const handleUpload = async (file: File) => {
    setUploading(true);
    setError(null);
    setInfoMessage(null);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const res = await uploadCapture(file, assessmentId);
      const failed = /failed|unsupported|empty|exceeds/i.test(res.message || '');
      setInfoMessage(res.message || (failed ? 'Capture analysis failed' : 'Capture uploaded and analyzed'));
      if (failed) setError(res.message || 'Capture analysis failed');
      await fetchData();
      setRefreshTick((t) => t + 1);
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setUploading(false);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) handleUpload(file);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleSelectCapture = (id: string) => {
    setSelectedId((prev) => (prev === id ? null : id));
    setPacketsPage(1);
    setPacketProtocol('');
  };

  const handleStartCapture = async () => {
    setError(null);
    setInfoMessage(null);
    setCapturing(true);
    setElapsed(0);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const res = await startLiveCapture(selectedInterface, assessmentId);
      const ok = !!res.data && typeof res.data === 'object' && 'id' in res.data;
      if (ok) {
        setActiveCaptureId(String((res.data as { id: string }).id));
        setInfoMessage(res.message || 'Live capture started');
      } else {
        setCapturing(false);
        setError(res.message || 'Live capture failed to start');
      }
      await fetchData();
    } catch (e) {
      setCapturing(false);
      setError(getApiError(e));
    }
  };

  const handleStopCapture = async () => {
    if (!activeCaptureId) return;
    setError(null);
    setInfoMessage(null);
    try {
      const res = await stopLiveCapture(activeCaptureId);
      setInfoMessage(res.message || 'Capture stopped');
      setCapturing(false);
      setActiveCaptureId(null);
      setLiveStatus(null);
      setElapsed(0);
      await fetchData();
      setRefreshTick((t) => t + 1);
    } catch (e) {
      setError(getApiError(e));
    }
  };

  const hasData = captures.length > 0 || protocolStats.length > 0;
  const selected = captures.find((c) => c.id === selectedId) || null;
  const totalPages = Math.max(1, Math.ceil(packetsTotal / PACKET_PAGE_SIZE));
  const protocolOptions = captureDetail
    ? Object.keys(captureDetail.protocol_stats || {}).sort()
    : [];

  const renderDetail = () => {
    if (!selected && !captureDetail) return null;
    if (detailLoading) {
      return <LoadingSpinner size="md" text="Loading capture analysis..." />;
    }
    if (detailError) {
      return (
        <div className="p-3 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">
          {detailError}
        </div>
      );
    }
    if (!captureDetail) return null;

    const detail = captureDetail;
    return (
      <div className="space-y-6">
        <Card
          title={`Analysis - ${detail.filename}`}
          subtitle={`${detail.packets} packets | ${detail.conversation_count ?? 0} conversations | analyzed ${detail.date}`}
        >
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-4">
              <p className="text-xs text-surface-400 uppercase font-medium">Packets</p>
              <p className="text-xl font-semibold mt-1">{detail.packets}</p>
            </div>
            <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-4">
              <p className="text-xs text-surface-400 uppercase font-medium">File Size</p>
              <p className="text-xl font-semibold mt-1">{detail.size}</p>
            </div>
            <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-4">
              <p className="text-xs text-surface-400 uppercase font-medium">Duration</p>
              <p className="text-xl font-semibold mt-1">{detail.duration}</p>
            </div>
            <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-4">
              <p className="text-xs text-surface-400 uppercase font-medium">Total Bytes</p>
              <p className="text-xl font-semibold mt-1">{formatBytes(detail.total_bytes)}</p>
            </div>
            <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-4">
              <p className="text-xs text-surface-400 uppercase font-medium">Avg Packet</p>
              <p className="text-xl font-semibold mt-1">{detail.avg_packet_size} B</p>
            </div>
            <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-4">
              <p className="text-xs text-surface-400 uppercase font-medium">Packets/sec</p>
              <p className="text-xl font-semibold mt-1">{detail.packets_per_second}</p>
            </div>
          </div>
          {(detail.started_at || detail.ended_at) && (
            <div className="mt-4 text-xs text-surface-400 font-mono">
              {detail.started_at && <span>Start: {new Date(detail.started_at).toLocaleString()} &nbsp; </span>}
              {detail.ended_at && <span>End: {new Date(detail.ended_at).toLocaleString()}</span>}
            </div>
          )}
        </Card>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card title="Protocol Distribution">
            {Object.keys(detail.protocol_stats || {}).length > 0 ? (
              <div className="space-y-3">
                {Object.entries(detail.protocol_stats)
                  .sort(([, a], [, b]) => (b as number) - (a as number))
                  .map(([proto, count]) => {
                    const pct = detail.packets > 0 ? ((count as number) / detail.packets) * 100 : 0;
                    return (
                      <div key={proto}>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-surface-700 dark:text-surface-300">{proto}</span>
                          <span className="text-surface-400">{pct.toFixed(1)}% ({count} pkts)</span>
                        </div>
                        <div className="h-1.5 bg-surface-200 dark:bg-surface-700 rounded-full overflow-hidden">
                          <div className="h-full bg-primary-500 rounded-full" style={{ width: `${Math.min(pct, 100)}%` }} />
                        </div>
                      </div>
                    );
                  })}
              </div>
            ) : (
              <p className="text-sm text-surface-400">No protocol data for this capture.</p>
            )}
          </Card>

          <Card title="Conversations" subtitle={`${conversations.length} source/destination pairs`}>
            {conversations.length === 0 ? (
              <p className="text-sm text-surface-400">No conversations extracted.</p>
            ) : (
              <div className="overflow-x-auto max-h-72 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-surface-200 dark:border-surface-700">
                      <th className="text-left px-3 py-2 text-xs font-medium text-surface-500 uppercase">Source</th>
                      <th className="text-left px-3 py-2 text-xs font-medium text-surface-500 uppercase">Destination</th>
                      <th className="text-center px-3 py-2 text-xs font-medium text-surface-500 uppercase">Protocol</th>
                      <th className="text-right px-3 py-2 text-xs font-medium text-surface-500 uppercase">Packets</th>
                      <th className="text-right px-3 py-2 text-xs font-medium text-surface-500 uppercase">Bytes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                    {conversations.map((conv) => (
                      <tr key={conv.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                        <td className="px-3 py-2 font-mono text-xs text-surface-900 dark:text-surface-100">
                          {conv.src_ip}
                          {conv.src_port != null ? `:${conv.src_port}` : ''}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-surface-900 dark:text-surface-100">
                          {conv.dst_ip}
                          {conv.dst_port != null ? `:${conv.dst_port}` : ''}
                        </td>
                        <td className="px-3 py-2 text-center">
                          <Badge variant="default">{conv.protocol}</Badge>
                        </td>
                        <td className="px-3 py-2 text-right text-surface-600 dark:text-surface-400">{conv.packets}</td>
                        <td className="px-3 py-2 text-right text-surface-600 dark:text-surface-400">{formatBytes(conv.bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </div>

        <Card title="Packet List" subtitle={`${packetsTotal} packets`}>
          {protocolOptions.length > 0 && (
            <div className="flex items-center gap-2 mb-3">
              <label className="text-xs text-surface-400 uppercase font-medium">Protocol</label>
              <select
                className="text-sm rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50 dark:bg-surface-800 px-2 py-1"
                value={packetProtocol}
                onChange={(e) => {
                  setPacketProtocol(e.target.value);
                  setPacketsPage(1);
                }}
              >
                <option value="">All</option>
                {protocolOptions.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>
          )}
          {packets.length === 0 ? (
            <p className="text-sm text-surface-400 py-4">
              {detailLoading ? 'Loading packets...' : 'No packets match the current filter.'}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-surface-200 dark:border-surface-700">
                    <th className="text-right px-3 py-2 text-xs font-medium text-surface-500 uppercase">#</th>
                    <th className="text-left px-3 py-2 text-xs font-medium text-surface-500 uppercase">Time</th>
                    <th className="text-left px-3 py-2 text-xs font-medium text-surface-500 uppercase">Source</th>
                    <th className="text-left px-3 py-2 text-xs font-medium text-surface-500 uppercase">Destination</th>
                    <th className="text-center px-3 py-2 text-xs font-medium text-surface-500 uppercase">Protocol</th>
                    <th className="text-right px-3 py-2 text-xs font-medium text-surface-500 uppercase">Length</th>
                    <th className="text-left px-3 py-2 text-xs font-medium text-surface-500 uppercase">Info</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                  {packets.map((pkt) => (
                    <tr key={pkt.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                      <td className="px-3 py-2 text-right text-surface-400 font-mono text-xs">{pkt.seq}</td>
                      <td className="px-3 py-2 font-mono text-xs text-surface-600 dark:text-surface-400">
                        {pkt.timestamp ? new Date(pkt.timestamp).toLocaleTimeString() : '-'}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-surface-900 dark:text-surface-100">
                        {pkt.src_ip || '-'}
                        {pkt.src_port != null ? `:${pkt.src_port}` : ''}
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-surface-900 dark:text-surface-100">
                        {pkt.dst_ip || '-'}
                        {pkt.dst_port != null ? `:${pkt.dst_port}` : ''}
                      </td>
                      <td className="px-3 py-2 text-center">
                        <Badge variant={pkt.protocol === 'TCP' || pkt.protocol === 'HTTP' || pkt.protocol === 'HTTPS' ? 'success' : 'default'}>
                          {pkt.protocol}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-right text-surface-600 dark:text-surface-400">{pkt.length}</td>
                      <td className="px-3 py-2 text-xs text-surface-600 dark:text-surface-400 truncate max-w-[280px]" title={pkt.info || ''}>
                        {pkt.info || '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {packetsTotal > PACKET_PAGE_SIZE && (
            <div className="flex items-center justify-between mt-4">
              <span className="text-xs text-surface-400">
                Page {packetsPage} of {totalPages} ({packetsTotal} packets)
              </span>
              <div className="flex gap-2">
                <Button variant="secondary" disabled={packetsPage <= 1} onClick={() => setPacketsPage((p) => p - 1)}>
                  Previous
                </Button>
                <Button variant="secondary" disabled={packetsPage >= totalPages} onClick={() => setPacketsPage((p) => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <Card title="Packet Capture" subtitle="Capture live traffic or upload PCAP files for analysis">
        <div className="flex flex-wrap items-end gap-3 mb-4">
          <div>
            <label className="block text-xs text-surface-400 uppercase font-medium mb-1">Interface</label>
            <select
              className="text-sm rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50 dark:bg-surface-800 px-2 py-2 min-w-[260px]"
              value={selectedInterface}
              disabled={capturing}
              onChange={(e) => setSelectedInterface(e.target.value)}
            >
              <option value="auto">Auto (loopback / default)</option>
              {interfaces.map((iface) => (
                <option key={iface.id} value={iface.id}>
                  {iface.description || iface.name}
                </option>
              ))}
            </select>
          </div>
          <Button variant="secondary" onClick={handleStartCapture} disabled={capturing || uploading}>
            {capturing ? 'Capturing...' : 'Start Capture'}
          </Button>
          <Button variant="danger" onClick={handleStopCapture} disabled={!capturing || !activeCaptureId}>
            Stop Capture
          </Button>
          <Button variant="primary" onClick={() => fileInputRef.current?.click()} disabled={uploading || capturing}>
            {uploading ? 'Uploading...' : 'Upload PCAP'}
          </Button>
          <input type="file" ref={fileInputRef} accept=".pcap,.pcapng,.cap" className="hidden" onChange={handleFileChange} />
        </div>
        {interfacesError && !capturing && (
          <p className="text-xs text-warning mb-3">Interfaces unavailable: {interfacesError}</p>
        )}
        {capturing && (
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2 mb-4 p-3 rounded-lg border border-critical/30 bg-critical/5 text-sm">
            <span className="flex items-center gap-2 font-medium text-surface-800 dark:text-surface-100">
              <span className="w-2 h-2 rounded-full bg-critical animate-pulse" />
              Capturing
            </span>
            <span className="text-surface-600 dark:text-surface-400">
              Interface: <span className="font-mono">{liveStatus?.interface || (interfaces.find((i) => i.id === selectedInterface)?.description ?? selectedInterface)}</span>
            </span>
            <span className="text-surface-600 dark:text-surface-400">
              Duration: <span className="font-mono">{formatDuration(liveStatus?.duration_seconds ?? elapsed)}</span>
            </span>
            <span className="text-surface-600 dark:text-surface-400">
              Packets: <span className="font-mono">{liveStatus?.packets ?? 0}</span>
            </span>
            <span className="text-surface-600 dark:text-surface-400">
              Size: <span className="font-mono">{formatBytes(liveStatus?.bytes ?? 0)}</span>
            </span>
          </div>
        )}
        {error && (
          <div className="p-3 mb-4 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">{error}</div>
        )}
        {infoMessage && !error && (
          <div className="p-3 mb-4 text-success bg-success/10 rounded-lg border border-success/20 text-sm">{infoMessage}</div>
        )}
      </Card>

      {loading ? (
        <LoadingSpinner size="md" text="Loading packet captures..." />
      ) : !hasData ? (
        <Card title="No Captures Yet">
          <div className="text-center py-12 text-surface-400">
            <p className="text-lg font-medium mb-1">No packet captures available</p>
            <p className="text-sm">Upload a PCAP file to begin analysis.</p>
          </div>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card title="Active Capture">
              {capturing ? (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <span className="w-2 h-2 rounded-full bg-critical animate-pulse" />
                    <span className="text-sm font-medium text-surface-700 dark:text-surface-300">
                      Capturing on {liveStatus?.interface || selectedInterface}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-3">
                      <p className="text-xs text-surface-400 uppercase font-medium">Duration</p>
                      <p className="text-lg font-semibold mt-1 font-mono">{formatDuration(liveStatus?.duration_seconds ?? elapsed)}</p>
                    </div>
                    <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-3">
                      <p className="text-xs text-surface-400 uppercase font-medium">Packets</p>
                      <p className="text-lg font-semibold mt-1 font-mono">{liveStatus?.packets ?? 0}</p>
                    </div>
                    <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-3">
                      <p className="text-xs text-surface-400 uppercase font-medium">Captured Bytes</p>
                      <p className="text-lg font-semibold mt-1 font-mono">{formatBytes(liveStatus?.bytes ?? 0)}</p>
                    </div>
                  </div>
                  <p className="text-sm text-surface-400 mt-3">
                    Click "Stop Capture" to finalize and analyze the captured traffic.
                  </p>
                </div>
              ) : (
                <p className="text-sm text-surface-400">No active capture. Select an interface and start a live capture.</p>
              )}
            </Card>

            <Card title="Protocol Distribution">
              {protocolStats.length > 0 ? (
                <div className="space-y-3">
                  {protocolStats.map((p) => (
                    <div key={p.protocol}>
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-surface-700 dark:text-surface-300">{p.protocol}</span>
                        <span className="text-surface-400">{p.percentage}% ({p.packets} pkts)</span>
                      </div>
                      <div className="h-1.5 bg-surface-200 dark:bg-surface-700 rounded-full overflow-hidden">
                        <div className="h-full bg-primary-500 rounded-full" style={{ width: `${Math.min(p.percentage, 100)}%` }} />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-surface-400">No protocol data available yet.</p>
              )}
            </Card>
          </div>

          <Card title="Capture History" subtitle={`${captures.length} captures - click a capture to view analysis`}>
            {captures.length === 0 ? (
              <div className="text-center py-8 text-surface-400">
                <p className="text-sm">No captures recorded for this assessment.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-surface-200 dark:border-surface-700">
                      <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Filename</th>
                      <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Size</th>
                      <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Packets</th>
                      <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Duration</th>
                      <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                    {captures.map((cap) => (
                      <tr
                        key={cap.id}
                        onClick={() => handleSelectCapture(cap.id)}
                        className={`cursor-pointer hover:bg-surface-50 dark:hover:bg-surface-800/50 ${
                          selectedId === cap.id ? 'bg-primary-500/10' : ''
                        }`}
                      >
                        <td className="px-4 py-3 font-mono text-xs text-surface-900 dark:text-surface-100">{cap.filename}</td>
                        <td className="px-4 py-3 text-right text-surface-600 dark:text-surface-400">{cap.size}</td>
                        <td className="px-4 py-3 text-right text-surface-600 dark:text-surface-400">{cap.packets}</td>
                        <td className="px-4 py-3 text-center text-surface-600 dark:text-surface-400">{cap.duration}</td>
                        <td className="px-4 py-3 text-center">
                          <Badge variant={cap.status === 'completed' ? 'success' : cap.status === 'capturing' ? 'warning' : 'default'}>
                            {cap.status}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          {selected && renderDetail()}
        </>
      )}
    </div>
  );
}
