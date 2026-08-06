import { useEffect, useRef, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { ProgressBar } from '../components/ui/ProgressBar';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { getPorts, startPortScan } from '../services/portService';
import { getHosts } from '../services/hostService';
import { createAssessment, getAssessment, startAssessment } from '../services/assessmentService';
import { getActiveAssessmentId, setActiveAssessment, useAssessmentChangeTick } from '../services/assessmentStore';
import type { AssessmentStage } from '../types/assessment';
import type { Port } from '../types/port';
import type { Host } from '../types/host';
import { getApiError } from '../services/api';

type ScanMode = 'full_assessment' | 'port_scan';

const STAGE_ICONS: Record<string, string> = {
  host_discovery: '\u{1F5A5}',
  port_scan: '\u{1F4E1}',
  service_intelligence: '\u{1F50D}',
  vulnerability_assessment: '\u{26A0}',
  cve_intelligence: '\u{1F9E0}',
  exploit_verification: '\u{26A1}',
};

const STAGE_LABELS: Record<string, string> = {
  host_discovery: 'Running Host Discovery...',
  port_scan: 'Running Port Scan...',
  service_intelligence: 'Running Service Intelligence...',
  vulnerability_assessment: 'Running Vulnerability Assessment...',
  cve_intelligence: 'Running CVE Intelligence...',
  exploit_verification: 'Running Exploit Verification...',
};

function getStatusMessage(
  status: string | undefined,
  stages: AssessmentStage[] | undefined,
): string {
  if (!status || status === 'pending') return 'Starting assessment...';
  if (status === 'running') {
    if (!stages || stages.length === 0) return 'Starting assessment...';
    const active = stages.find((s) => s.status === 'running');
    if (active) return STAGE_LABELS[active.stage_name] || `Running ${active.display_name}...`;
    const pending = stages.find((s) => s.status === 'pending');
    if (pending) return `Preparing ${pending.display_name}...`;
    if (stages.some((s) => s.status === 'completed')) return 'Assessment running...';
    return 'Starting assessment...';
  }
  if (status === 'completed') return 'Assessment Completed';
  if (status === 'failed') return 'Assessment Failed';
  if (status === 'cancelled') return 'Assessment Cancelled';
  return 'Starting assessment...';
}

export function Scanning() {
  const [mode, setMode] = useState<ScanMode>('full_assessment');
  const [ports, setPorts] = useState<Port[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [target, setTarget] = useState('192.168.56.0/24');
  const [assessmentName, setAssessmentName] = useState('');
  const [scanType, setScanType] = useState('tcp_syn');
  const [scanProfile, setScanProfile] = useState('top_ports');
  const [customPorts, setCustomPorts] = useState('22,80,443');
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [assessmentStatus, setAssessmentStatus] = useState<string | undefined>();
  const [stages, setStages] = useState<AssessmentStage[]>([]);
  const [overallProgress, setOverallProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const tick = useAssessmentChangeTick();

  const clearPoll = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  const startPolling = (id: string) => {
    clearPoll();
    pollRef.current = setInterval(async () => {
      try {
        const res = await getAssessment(id);
        const a = res.data;
        setAssessmentStatus(a.status);
        if (a.progress) {
          setStages(a.progress.stages);
          setOverallProgress(a.progress.overall_progress);
        }
        setStatusMessage(getStatusMessage(a.status, a.progress?.stages));
        if (a.status === 'completed' || a.status === 'failed' || a.status === 'cancelled') {
          clearPoll();
          setScanning(false);
          refreshData();
        }
      } catch {
        clearPoll();
        setScanning(false);
        setError('Failed to fetch assessment progress');
      }
    }, 2000);
  };

  const refreshData = () => {
    const assessmentId = getActiveAssessmentId() ?? undefined;
    Promise.all([
      getPorts(assessmentId).then(r => r.data).catch(() => [] as Port[]),
      getHosts(assessmentId).then(r => r.data).catch(() => [] as Host[]),
    ]).then(([portsData, hostsData]) => {
      setPorts(portsData);
      setHosts(hostsData);
    });
  };

  useEffect(() => {
    return () => clearPoll();
  }, []);

  useEffect(() => {
    refreshData();
    setLoading(false);
  }, [tick]);

  const handleStartPortScan = async () => {
    setError(null);
    if (!target.trim()) {
      setError('Please enter a target range');
      return;
    }
    if (scanProfile === 'custom_range' && !customPorts.trim()) {
      setError('Please enter a port range for the custom profile');
      return;
    }
    setScanning(true);
    setStatusMessage('Starting port scan...');
    setAssessmentStatus(undefined);
    setStages([]);
    setOverallProgress(0);
    try {
      const res = await startPortScan({
        target: target.trim(),
        scan_type: scanType as 'tcp_syn' | 'tcp_connect' | 'udp_scan',
        scan_profile: scanProfile as 'top_ports' | 'custom_range' | 'all_ports',
        ports: scanProfile === 'custom_range' ? customPorts.trim() : undefined,
      });
      const assessmentId = res.data?.assessment_id;
      if (assessmentId) {
        setActiveAssessment(assessmentId, `Port Scan - ${target}`, 'running');
        setStatusMessage(getStatusMessage('running', []));
        startPolling(assessmentId);
      } else {
        refreshData();
        setScanning(false);
      }
    } catch (e) {
      setError(getApiError(e));
      setScanning(false);
    }
  };

  const handleStartAssessment = async () => {
    if (!assessmentName.trim()) {
      setError('Please enter an assessment name');
      return;
    }
    setError(null);
    setScanning(true);
    setStatusMessage('Creating assessment...');
    setAssessmentStatus(undefined);
    setStages([]);
    setOverallProgress(0);
    try {
      const createRes = await createAssessment({
        name: assessmentName.trim(),
        scan_type: 'full_assessment',
        target: target.trim(),
      });
      const id = createRes.data.id;
      setActiveAssessment(id, createRes.data.name, 'draft');
      setStatusMessage('Starting assessment...');
      await startAssessment(id);
      setAssessmentStatus('running');
      setStatusMessage(getStatusMessage('running', []));
      startPolling(id);
    } catch (e) {
      setScanning(false);
      setError(getApiError(e));
    }
  };

  const openPorts = ports.filter((p) => p.state === 'open');
  const stateCounts = {
    open: openPorts.length,
    filtered: ports.filter((p) => p.state === 'filtered').length,
    closed: ports.filter((p) => p.state === 'closed').length,
  };

  return (
    <div className="space-y-6">
      <Card title="Scan Mode" subtitle="Choose between a full assessment or a standalone port scan">
        <div className="flex gap-3 mb-2">
          <Button
            variant={mode === 'full_assessment' ? 'primary' : 'secondary'}
            onClick={() => setMode('full_assessment')}
          >
            Full Assessment
          </Button>
          <Button
            variant={mode === 'port_scan' ? 'primary' : 'secondary'}
            onClick={() => setMode('port_scan')}
          >
            Port Scan Only
          </Button>
        </div>
      </Card>

      {error && (
        <div className="p-3 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm">
          {error}
        </div>
      )}

      {mode === 'full_assessment' ? (
        <Card title="Full Assessment" subtitle="Run the complete VAPT pipeline">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div>
              <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
                Assessment Name
              </label>
              <input
                type="text"
                className="input"
                placeholder="e.g., Quarterly Scan"
                value={assessmentName}
                onChange={(e) => setAssessmentName(e.target.value)}
                disabled={scanning}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
                Target
              </label>
              <input
                type="text"
                className="input font-mono w-full"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={scanning}
              />
            </div>
          </div>
          <div className="flex gap-3">
            <Button variant="primary" onClick={handleStartAssessment} disabled={scanning} loading={scanning}>
              {scanning ? 'Running...' : 'Start Full Assessment'}
            </Button>
          </div>

          {statusMessage && (
            <div className="mt-4">
              <p className="text-sm font-medium text-surface-700 dark:text-surface-300 mb-2">
                {statusMessage}
              </p>
              <ProgressBar
                value={overallProgress}
                color={assessmentStatus === 'completed' ? 'success' : assessmentStatus === 'failed' ? 'danger' : 'primary'}
                size="md"
                showLabel
              />
            </div>
          )}

          {stages.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mt-6">
              {stages.map((stage) => (
                <div
                  key={stage.stage_name}
                  className="p-4 rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50 dark:bg-surface-800/50"
                >
                  <div className="flex items-start justify-between mb-2">
                    <span className="text-2xl">
                      {STAGE_ICONS[stage.stage_name] || '\u{1F4CB}'}
                    </span>
                    <Badge
                      variant={
                        stage.status === 'completed'
                          ? 'success'
                          : stage.status === 'running'
                            ? 'warning'
                            : stage.status === 'failed'
                              ? 'danger'
                              : 'default'
                      }
                    >
                      {stage.status}
                    </Badge>
                  </div>
                  <h4 className="font-medium text-surface-900 dark:text-surface-100 text-sm">
                    {stage.display_name}
                  </h4>
                  <p className="text-xs text-surface-400 mt-1">
                    {stage.status === 'running' && `${stage.progress.toFixed(0)}% complete`}
                    {stage.status === 'completed' && 'Done'}
                    {stage.status === 'failed' && (stage.error_message || 'Failed')}
                    {stage.status === 'pending' && 'Waiting'}
                  </p>
                </div>
              ))}
            </div>
          )}
        </Card>
      ) : (
        <Card title="Port Scanner Configuration">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
            <div>
              <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Target</label>
              <input
                type="text"
                className="input font-mono w-full"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Scan Type</label>
              <select className="input w-full" value={scanType} onChange={(e) => setScanType(e.target.value)}>
                <option value="tcp_syn">TCP SYN Scan (-sS)</option>
                <option value="tcp_connect">TCP Connect Scan (-sT)</option>
                <option value="udp_scan">UDP Scan (-sU)</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Profile</label>
              <select className="input w-full" value={scanProfile} onChange={(e) => setScanProfile(e.target.value)}>
                <option value="top_ports">Top 1000 Ports</option>
                <option value="custom_range">Custom Range</option>
                <option value="all_ports">All Ports (1-65535)</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
                {scanProfile === 'custom_range' ? 'Port Range' : 'Hosts'}
              </label>
              {scanProfile === 'custom_range' ? (
                <input
                  type="text"
                  className="input font-mono w-full"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                />
              ) : (
                <div className="h-10 flex items-center text-sm text-surface-500">
                  {hosts.filter((h) => h.is_alive).length} alive hosts
                </div>
              )}
            </div>
          </div>
          <div className="flex gap-3">
            <Button variant="primary" onClick={handleStartPortScan} disabled={scanning} loading={scanning}>
              {scanning ? 'Scanning...' : 'Start Scan'}
            </Button>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="Open Ports" subtitle="Accessible services">
          <div className="text-3xl font-bold text-low">{stateCounts.open}</div>
        </Card>
        <Card title="Filtered" subtitle="Firewall protected">
          <div className="text-3xl font-bold text-warning">{stateCounts.filtered}</div>
        </Card>
        <Card title="Total Scanned" subtitle="All port records">
          <div className="text-3xl font-bold">{ports.length}</div>
        </Card>
      </div>

      {mode === 'port_scan' && scanning && (
        <Card title="Active Scan" subtitle={target}>
          <div className="mb-2 flex justify-between">
            <span className="text-sm font-medium text-surface-700 dark:text-surface-300">{statusMessage || 'Scan in progress...'}</span>
            <Badge variant="warning">Running</Badge>
          </div>
          {stages.length > 0 ? (
            <>
              <ProgressBar value={overallProgress} color="primary" showLabel />
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
                {stages.map((stage) => (
                  <div key={stage.stage_name} className="p-3 rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50 dark:bg-surface-800/50">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-surface-900 dark:text-surface-100">{stage.display_name}</span>
                      <Badge variant={stage.status === 'completed' ? 'success' : stage.status === 'running' ? 'warning' : 'default'}>
                        {stage.status}
                      </Badge>
                    </div>
                    <p className="text-xs text-surface-400">
                      {stage.status === 'running' && `${stage.progress.toFixed(0)}% complete`}
                      {stage.status === 'completed' && 'Done'}
                      {stage.status === 'pending' && 'Waiting'}
                    </p>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <ProgressBar value={overallProgress} color="primary" showLabel />
          )}
        </Card>
      )}

      <Card title="Scan Results" subtitle="Discovered ports and services">
        {loading ? (
          <LoadingSpinner size="sm" text="Loading port data..." />
        ) : ports.length === 0 ? (
          <div className="text-center py-8 text-surface-400">
            No ports found. Run a scan to discover open ports.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-200 dark:border-surface-700">
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Port</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Protocol</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">State</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Service</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Product</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                {ports.map((p) => (
                  <tr key={p.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                    <td className="px-4 py-3 font-mono font-medium text-surface-900 dark:text-surface-100">{p.port}</td>
                    <td className="px-4 py-3 uppercase text-xs text-surface-500">{p.protocol}</td>
                    <td className="px-4 py-3">
                      <Badge variant={p.state === 'open' ? 'success' : p.state === 'filtered' ? 'warning' : 'default'}>
                        {p.state}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-surface-600 dark:text-surface-400">
                      {p.services[0]?.name || '\u2014'}
                    </td>
                    <td className="px-4 py-3 text-surface-600 dark:text-surface-400">
                      {p.services[0]?.product || '\u2014'}
                    </td>
                    <td className="px-4 py-3 text-surface-600 dark:text-surface-400">
                      {p.services[0]?.version || '\u2014'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
