import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { AssessmentProgress } from '../components/assessment/AssessmentProgress';
import { ReportList } from '../components/assessment/ReportList';
import { SeveritySummary } from '../components/assessment/SeveritySummary';
import { Stat } from '../components/assessment/Stat';
import {
  computeRiskScore,
  formatDuration,
  SCAN_TYPE_LABELS,
  statusColor,
} from '../components/assessment/assessmentMeta';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { useToast } from '../hooks/useToast';
import { getApiError } from '../services/api';
import { getAssessmentSummary } from '../services/assessmentService';
import { getCVEStatistics } from '../services/cveService';
import { downloadReport, getReports, type Report } from '../services/reportService';

const RISK_LEVEL_BADGE: Record<string, 'danger' | 'warning' | 'success' | 'info' | 'default'> = {
  Critical: 'danger',
  High: 'warning',
  Medium: 'warning',
  Low: 'success',
  None: 'default',
};

function formatTimestamp(iso: string | null): string {
  if (!iso) return '—';
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

export function AssessmentOverview() {
  const { assessmentId } = useParams<{ assessmentId: string }>();
  const { addToast } = useToast();

  const [summary, setSummary] = useState<Awaited<ReturnType<typeof getAssessmentSummary>>['data'] | null>(null);
  const [cveTotal, setCveTotal] = useState<number | null>(null);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [loadingReports, setLoadingReports] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const fetchOverview = useCallback(async () => {
    if (!assessmentId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await getAssessmentSummary(assessmentId);
      setSummary(res.data);
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    fetchOverview();
  }, [fetchOverview]);

  useEffect(() => {
    if (!assessmentId) return;
    getCVEStatistics(assessmentId)
      .then((res) => setCveTotal(res.data.total_cves))
      .catch(() => setCveTotal(null));
  }, [assessmentId]);

  const fetchReports = useCallback(async () => {
    if (!assessmentId) return;
    setLoadingReports(true);
    try {
      const data = await getReports({ assessmentId });
      setReports(Array.isArray(data) ? data : []);
    } catch {
      setReports([]);
    } finally {
      setLoadingReports(false);
    }
  }, [assessmentId]);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleDownloadReport = async (report: Report) => {
    setDownloadingId(report.id);
    try {
      const blob = await downloadReport(report.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.title}.${report.format.toLowerCase()}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      addToast({ type: 'success', title: `Downloading ${report.title}` });
    } catch (e) {
      addToast({ type: 'error', title: 'Download failed', message: getApiError(e) });
    } finally {
      setDownloadingId(null);
    }
  };

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="md" text="Loading assessment overview..." />
      </div>
    );
  }

  if (error && !summary) {
    return (
      <Card title="Assessment Overview">
        <div className="p-4 rounded-lg border border-critical/20 bg-critical/10 text-critical text-sm">
          Failed to load assessment: {error}
          <button className="ml-3 underline" onClick={fetchOverview}>Retry</button>
        </div>
      </Card>
    );
  }

  if (!summary) return null;

  const risk = computeRiskScore(summary.severity_counts);
  const progressPercent = summary.progress?.overall_progress ?? summary.progress_percent ?? 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100 truncate">
              {summary.name}
            </h1>
            <Badge variant={statusColor(summary.status)}>{summary.status}</Badge>
          </div>
          <p className="text-sm text-surface-400 mt-1 font-mono">
            {summary.target}
            <span className="mx-2 text-surface-300 dark:text-surface-600">·</span>
            {SCAN_TYPE_LABELS[summary.scan_type] || summary.scan_type}
          </p>
          <p className="text-xs text-surface-400 mt-1 font-mono">ID: {summary.id}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="secondary" onClick={fetchOverview} loading={loading}>
            Refresh
          </Button>
          <Link to="/history">
            <Button size="sm" variant="ghost">← Back to History</Button>
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <Stat label="Risk Score" value={String(risk.score)} />
        <Stat label="Start Time" value={formatTimestamp(summary.started_at)} />
        <Stat label="End Time" value={formatTimestamp(summary.completed_at)} />
        <Stat label="Duration" value={formatDuration(summary.started_at, summary.completed_at, summary.duration_seconds)} />
        <Stat label="Progress" value={`${Math.round(progressPercent)}%`} />
        <Stat label="Hosts" value={String(summary.hosts_count)} />
        <Stat label="Open Ports" value={String(summary.ports_count)} />
        <Stat label="Services" value={String(summary.services_count)} />
        <Stat label="Vulnerabilities" value={String(summary.total_vulnerabilities)} />
        <Stat label="CVEs" value={cveTotal === null ? '—' : String(cveTotal)} />
        <Stat label="Exploits" value={String(summary.exploits_count)} />
        <Stat label="Reports" value={String(summary.reports_count)} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card title="Severity Summary" subtitle={`${summary.total_vulnerabilities} findings`}>
          <SeveritySummary counts={summary.severity_counts} total={summary.total_vulnerabilities} />
        </Card>

        <Card title="Risk Level" subtitle="Weighted severity score">
          <div className="flex items-center gap-4">
            <span className="text-4xl font-bold text-surface-900 dark:text-surface-100">{risk.score}</span>
            <div>
              <Badge variant={RISK_LEVEL_BADGE[risk.level] ?? 'default'} size="md">{risk.level}</Badge>
              <p className="text-xs text-surface-400 mt-2">
                {risk.total} findings assessed · {risk.score}/100
              </p>
            </div>
          </div>
        </Card>

        <Card title="Progress" subtitle="Pipeline stages">
          <AssessmentProgress
            progress={summary.progress}
            status={summary.status}
            overallPercent={summary.progress?.overall_progress ?? summary.progress_percent}
          />
        </Card>
      </div>

      {summary.error_message && (
        <div className="p-3 rounded-lg bg-critical/10 text-critical text-sm">
          {summary.error_message}
        </div>
      )}

      <Card title="Generated Reports" subtitle={`${reports.length} report${reports.length === 1 ? '' : 's'}`}>
        <ReportList
          reports={reports}
          loading={loadingReports}
          downloadingId={downloadingId}
          onDownload={handleDownloadReport}
        />
      </Card>
    </div>
  );
}
