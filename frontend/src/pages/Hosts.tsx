import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Table, type Column } from '../components/ui/Table';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import type { Host } from '../types/host';
import { getHosts, startDiscovery } from '../services/hostService';
import { getAssessment } from '../services/assessmentService';
import { getActiveAssessmentId, setActiveAssessment, useAssessmentChangeTick } from '../services/assessmentStore';
import { getApiError } from '../services/api';

const columns: Column<Host>[] = [
  {
    key: 'ip_address',
    header: 'IP Address',
    render: (h) => (
      <Link to={`/hosts/${h.id}`} className="font-mono text-sm text-primary-600 dark:text-primary-400 hover:underline">
        {h.ip_address}
      </Link>
    ),
  },
  { key: 'hostname', header: 'Hostname', render: (h) => h.hostname || '\u2014' },
  {
    key: 'os_name',
    header: 'Operating System',
    render: (h) =>
      h.os_name ? `${h.os_name} ${h.os_version || ''}${h.os_accuracy != null ? ` (${h.os_accuracy}%)` : ''}` : '\u2014',
  },
  { key: 'mac_address', header: 'MAC Address', render: (h) => <span className="font-mono text-xs text-surface-400">{h.mac_address || 'Unknown'}</span> },
  {
    key: 'status',
    header: 'Status',
    render: (h) => (
      <Badge variant={h.is_alive ? 'success' : 'default'}>
        {h.is_alive ? 'Alive' : 'Down'}
      </Badge>
    ),
  },
  {
    key: 'latency',
    header: 'Latency',
    align: 'right',
    render: (h) => (h.latency ? `${h.latency.toFixed(1)}ms` : '\u2014'),
  },
];

export function Hosts() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [target, setTarget] = useState('192.168.56.0/24');
  const [error, setError] = useState<string | null>(null);
  const tick = useAssessmentChangeTick();
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearPoll = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const loadHosts = () => {
    setLoading(true);
    getHosts(getActiveAssessmentId() ?? undefined)
      .then((res) => setHosts(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadHosts();
  }, [tick]);

  useEffect(() => {
    return () => clearPoll();
  }, []);

  const startPolling = (id: string) => {
    clearPoll();
    pollRef.current = setInterval(async () => {
      try {
        const res = await getAssessment(id);
        const status = res.data.status;
        if (status === 'completed' || status === 'failed' || status === 'cancelled') {
          clearPoll();
          setScanning(false);
          loadHosts();
        }
      } catch {
        clearPoll();
        setScanning(false);
      }
    }, 2000);
  };

  const handleRunDiscovery = async () => {
    setError(null);
    if (!target.trim()) {
      setError('Please enter a target range');
      return;
    }
    setScanning(true);
    try {
      const res = await startDiscovery({ target, scan_type: 'ping_sweep' });
      const assessmentId = res.data?.assessment_id;
      if (assessmentId) {
        setActiveAssessment(assessmentId, `Host Discovery - ${target}`);
        startPolling(assessmentId);
      } else {
        loadHosts();
        setScanning(false);
      }
    } catch (e) {
      setError(getApiError(e));
      setScanning(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card
        title="Host Discovery"
        subtitle="Live hosts in the network"
        action={
          <div className="flex items-center gap-2">
            <input
              type="text"
              className="input font-mono text-sm w-48"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={scanning}
              placeholder="Target range"
            />
            <Button variant="primary" size="sm" onClick={handleRunDiscovery} disabled={scanning} loading={scanning}>
              {scanning ? 'Discovering...' : 'Run Discovery'}
            </Button>
          </div>
        }
      >
        {error && (
          <div className="mb-4 p-3 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm">
            {error}
          </div>
        )}
        {loading ? (
          <LoadingSpinner size="sm" text="Loading hosts..." />
        ) : (
          <Table
            columns={columns}
            data={hosts}
            keyExtractor={(h) => h.id}
            emptyMessage="No hosts discovered. Run a discovery scan to find live hosts."
          />
        )}
      </Card>
    </div>
  );
}
