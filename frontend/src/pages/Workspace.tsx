import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { ProgressBar } from '../components/ui/ProgressBar';
import { createAssessment, getAssessment, startAssessment } from '../services/assessmentService';
import { setActiveAssessment } from '../services/assessmentStore';
import type { AssessmentStage } from '../types/assessment';
import { getApiError } from '../services/api';

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

export function Workspace() {
  const navigate = useNavigate();
  const [assessmentId, setAssessmentId] = useState<string | null>(null);
  const [status, setStatus] = useState<string | undefined>();
  const [stages, setStages] = useState<AssessmentStage[]>([]);
  const [overallProgress, setOverallProgress] = useState(0);
  const [target, setTarget] = useState('192.168.56.0/24');
  const [assessmentName, setAssessmentName] = useState('');
  const [busy, setBusy] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');
  const [error, setError] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

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
        setStatus(a.status);
        if (a.progress) {
          setStages(a.progress.stages);
          setOverallProgress(a.progress.overall_progress);
        }
        setStatusMessage(getStatusMessage(a.status, a.progress?.stages));
        if (a.status === 'completed' || a.status === 'failed' || a.status === 'cancelled') {
          clearPoll();
          setBusy(false);
        }
      } catch {
        clearPoll();
        setBusy(false);
        setError('Failed to fetch assessment progress');
      }
    }, 2000);
  };

  useEffect(() => {
    return () => clearPoll();
  }, []);

  const handleStartAssessment = async () => {
    if (!assessmentName.trim()) {
      setError('Please enter an assessment name');
      return;
    }
    if (!target.trim()) {
      setError('Please enter a target range');
      return;
    }
    setError(null);
    setBusy(true);
    setStatusMessage('Creating assessment...');
    setStatus(undefined);
    setStages([]);
    setOverallProgress(0);
    try {
      const createRes = await createAssessment({
        name: assessmentName.trim(),
        scan_type: 'full_assessment',
        target: target.trim(),
      });
      const id = createRes.data.id;
      setAssessmentId(id);
      setActiveAssessment(id, createRes.data.name);
      setStatusMessage('Starting assessment...');
      await startAssessment(id);
      setStatus('running');
      setStatusMessage(getStatusMessage('running', []));
      startPolling(id);
    } catch (e) {
      setBusy(false);
      setError(getApiError(e));
    }
  };

  const displayProgress = status === 'completed' ? 100 : overallProgress;

  return (
    <div className="space-y-6">
      <Card title="Assessment Configuration" subtitle="Define and run a full VAPT assessment">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
              Assessment Name
            </label>
            <input
              type="text"
              className="input"
              placeholder="e.g., Internal Lab Assessment Q3"
              value={assessmentName}
              onChange={(e) => setAssessmentName(e.target.value)}
              disabled={busy}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
              Target Range
            </label>
            <input
              type="text"
              className="input font-mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={busy}
            />
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm">
            {error}
          </div>
        )}

        <div className="flex gap-3">
          <Button variant="primary" size="lg" onClick={handleStartAssessment} disabled={busy} loading={busy}>
            Start Full Assessment
          </Button>
          <Button variant="secondary" size="lg" onClick={() => navigate('/scanning')}>
            Custom Assessment
          </Button>
        </div>
      </Card>

      <Card title="Assessment Progress" subtitle="6-step VAPT workflow">
        {statusMessage && (
          <div className="mb-4">
            <p className="text-sm font-medium text-surface-700 dark:text-surface-300">
              {statusMessage}
            </p>
          </div>
        )}

        <div className="mb-6">
          <ProgressBar
            value={displayProgress}
            color={status === 'completed' ? 'success' : status === 'failed' ? 'danger' : 'primary'}
            size="md"
            showLabel
          />
        </div>

        {busy && !assessmentId && (
          <div className="text-center py-4 text-sm text-surface-400">
            No active assessment
          </div>
        )}

        {(!busy || assessmentId) && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {stages.length === 0 && !busy ? (
              <div className="col-span-full text-center py-8 text-surface-400 text-sm">
                Run an assessment to see progress here
              </div>
            ) : (
              stages.map((stage) => (
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
              ))
            )}
          </div>
        )}
      </Card>

      <Card title="Quick Actions">
        <div className="flex flex-wrap gap-3">
          <Button variant="primary" onClick={() => navigate('/hosts')}>New Host Discovery</Button>
          <Button variant="secondary" onClick={() => navigate('/scanning')}>Quick Port Scan</Button>
          <Button variant="secondary" onClick={() => navigate('/vulnerabilities')}>Vulnerability Scan</Button>
          <Button variant="secondary" onClick={() => navigate('/reports')}>Generate Report</Button>
        </div>
      </Card>
    </div>
  );
}
