import { useCallback, useEffect, useRef, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { getApiError } from '../services/api';
import {
  getCaptureProtocols,
  getCaptures,
  startLiveCapture,
  stopLiveCapture,
  uploadCapture,
  type PacketCapture,
  type ProtocolStat,
} from '../services/captureService';
import { getActiveAssessmentId, useAssessmentChangeTick } from '../services/assessmentStore';

export function Packets() {
  const [captures, setCaptures] = useState<PacketCapture[]>([]);
  const [protocolStats, setProtocolStats] = useState<ProtocolStat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [activeCaptureId, setActiveCaptureId] = useState<string | null>(null);
  const [infoMessage, setInfoMessage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const tick = useAssessmentChangeTick();

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

  const handleUpload = async (file: File) => {
    setUploading(true);
    setError(null);
    setInfoMessage(null);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const res = await uploadCapture(file, assessmentId);
      const failed = /failed|unsupported|empty/i.test(res.message || '');
      setInfoMessage(res.message || (failed ? 'Capture analysis failed' : 'Capture uploaded and analyzed'));
      if (failed) setError(res.message || 'Capture analysis failed');
      await fetchData();
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

  const handleStartCapture = async () => {
    setError(null);
    setInfoMessage(null);
    setCapturing(true);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const res = await startLiveCapture('any', assessmentId);
      if (res.data && typeof res.data === 'object' && 'id' in res.data) {
        setActiveCaptureId(String((res.data as { id: string }).id));
      }
      setInfoMessage(res.message || 'Live capture started');
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
      await fetchData();
    } catch (e) {
      setError(getApiError(e));
    }
  };

  const hasData = captures.length > 0 || protocolStats.length > 0;

  return (
    <div className="space-y-6">
      <Card title="Packet Capture" subtitle="Upload PCAP files for analysis on the lab network">
        <div className="flex flex-wrap gap-3 mb-6">
          <Button variant="secondary" onClick={handleStartCapture} disabled={capturing || uploading}>
            Start Capture
          </Button>
          <Button variant="danger" onClick={handleStopCapture} disabled={!capturing || !activeCaptureId}>
            Stop Capture
          </Button>
          <Button variant="primary" onClick={() => fileInputRef.current?.click()} disabled={uploading || capturing}>
            {uploading ? 'Uploading...' : 'Upload PCAP'}
          </Button>
          <input type="file" ref={fileInputRef} accept=".pcap,.pcapng,.cap" className="hidden" onChange={handleFileChange} />
        </div>
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
                    <span className="text-sm font-medium text-surface-700 dark:text-surface-300">Capturing traffic...</span>
                  </div>
                  <p className="text-sm text-surface-400">
                    Click "Stop Capture" to finalize and analyze the captured traffic.
                  </p>
                </div>
              ) : (
                <p className="text-sm text-surface-400">No active capture. Upload a PCAP file or start a live capture.</p>
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

          <Card title="Capture History" subtitle={`${captures.length} captures`}>
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
                      <tr key={cap.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
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
        </>
      )}
    </div>
  );
}
