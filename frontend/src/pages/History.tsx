import { useCallback, useContext, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import { ReportList } from '../components/assessment/ReportList';
import { SeverityChips } from '../components/assessment/SeverityChips';
import { SeveritySummary } from '../components/assessment/SeveritySummary';
import { Stat } from '../components/assessment/Stat';
import { AssessmentProgress } from '../components/assessment/AssessmentProgress';
import {
  formatDuration,
  formatSeconds,
  progressColor,
  SCAN_TYPE_LABELS,
  STAGE_LABELS,
  statusColor,
} from '../components/assessment/assessmentMeta';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { ProgressBar } from '../components/ui/ProgressBar';
import { useToast } from '../hooks/useToast';
import type { Artifact, ArtifactContent, ArtifactFile } from '../types/artifact';
import type { Assessment, AssessmentSummary } from '../types/assessment';
import { getArtifactFiles, getArtifacts, downloadArtifactFile } from '../services/artifactService';
import {
  cloneAssessment,
  deleteAssessment,
  getAssessments,
  getAssessmentSummary,
  startAssessment,
} from '../services/assessmentService';
import apiClient from '../services/api';
import { getApiError } from '../services/api';
import { setActiveAssessment, useAssessmentChangeTick } from '../services/assessmentStore';
import { downloadReport, generateReport, getReports, type Report } from '../services/reportService';

const SCAN_TYPE_OPTIONS = ['', 'full_assessment', 'host_discovery', 'port_scan', 'service_enum', 'vuln_scan'];

const STATUS_OPTIONS = ['', 'draft', 'completed', 'failed', 'running', 'pending', 'cancelled'];

const DELETE_PRESETS = [
  { value: 'last_15m', label: 'Last 15 Minutes' },
  { value: 'last_1h', label: 'Last 1 Hour' },
  { value: 'today', label: 'Today' },
  { value: 'last_7d', label: 'Last 7 Days' },
  { value: 'last_30d', label: 'Last 30 Days' },
  { value: 'last_3m', label: 'Last 3 Months' },
  { value: 'last_6m', label: 'Last 6 Months' },
  { value: 'last_1y', label: 'Last 1 Year' },
  { value: 'custom', label: 'Custom Date Range' },
  { value: 'all', label: 'Delete All History' },
];

type Tab = 'overview' | 'progress' | 'reports' | 'artifacts';

export function History() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { hasRole } = useContext(AuthContext);
  const isAdmin = hasRole('administrator');

  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [statusFilter, setStatusFilter] = useState('');
  const [scanTypeFilter, setScanTypeFilter] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [targetFilter, setTargetFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  const [openMenuId, setOpenMenuId] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Assessment | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [cloningId, setCloningId] = useState<string | null>(null);
  const [startingId, setStartingId] = useState<string | null>(null);

  const [detailAssessment, setDetailAssessment] = useState<AssessmentSummary | null>(null);
  const [detailTab, setDetailTab] = useState<Tab>('overview');
  const [loadingDetail, setLoadingDetail] = useState(false);

  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null);
  const [files, setFiles] = useState<ArtifactFile[]>([]);
  const [fileContent, setFileContent] = useState<ArtifactContent | null>(null);
  const [loadingArtifacts, setLoadingArtifacts] = useState(false);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [loadingContent, setLoadingContent] = useState(false);

  const [reports, setReports] = useState<Report[]>([]);
  const [loadingReports, setLoadingReports] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [reportType, setReportType] = useState('executive');
  const [reportFormat, setReportFormat] = useState('json');
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const [deletePreset, setDeletePreset] = useState('');
  const [deleteFrom, setDeleteFrom] = useState('');
  const [deleteTo, setDeleteTo] = useState('');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const tick = useAssessmentChangeTick();

  const searchTimer = useRef<number | null>(null);

  useEffect(() => {
    if (searchTimer.current) window.clearTimeout(searchTimer.current);
    searchTimer.current = window.setTimeout(() => setSearch(searchInput.trim()), 350);
    return () => {
      if (searchTimer.current) window.clearTimeout(searchTimer.current);
    };
  }, [searchInput]);

  const fetchAssessments = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAssessments({
        status: statusFilter || undefined,
        scanType: scanTypeFilter || undefined,
        search: search || undefined,
        target: targetFilter || undefined,
        dateFrom: dateFrom || undefined,
        dateTo: dateTo || undefined,
        perPage: 100,
      });
      setAssessments(res.data);
    } catch {
      setError('Failed to load assessment history.');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, scanTypeFilter, search, targetFilter, dateFrom, dateTo, tick]);

  useEffect(() => { fetchAssessments(); }, [fetchAssessments]);

  const hasActive = assessments.some((a) => a.status === 'running' || a.status === 'pending');
  useEffect(() => {
    if (!hasActive) return;
    const interval = window.setInterval(fetchAssessments, 5000);
    return () => window.clearInterval(interval);
  }, [hasActive, fetchAssessments]);

  const handleRestore = (assessment: Assessment) => {
    if (assessment.status === 'draft') {
      addToast({
        type: 'warning',
        title: 'Draft assessment',
        message: `"${assessment.name}" has no scan data. Start the assessment first to generate results.`,
      });
      return;
    }
    setActiveAssessment(assessment.id, assessment.name, assessment.status);
    navigate('/');
  };

  const handleClone = async (assessment: Assessment) => {
    setCloningId(assessment.id);
    try {
      const res = await cloneAssessment(assessment.id);
      addToast({ type: 'success', title: 'Assessment cloned', message: res.message });
      await fetchAssessments();
    } catch (e) {
      addToast({ type: 'error', title: 'Clone failed', message: getApiError(e) });
    } finally {
      setCloningId(null);
    }
  };

  const handleStartDraft = async (assessment: Assessment) => {
    setStartingId(assessment.id);
    try {
      await startAssessment(assessment.id);
      addToast({ type: 'success', title: 'Assessment started', message: `"${assessment.name}" is now running.` });
      setActiveAssessment(assessment.id, assessment.name, 'running');
      navigate('/scanning');
    } catch (e) {
      addToast({ type: 'error', title: 'Start failed', message: getApiError(e) });
    } finally {
      setStartingId(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      const res = await deleteAssessment(deleteTarget.id);
      addToast({ type: 'success', title: 'Assessment deleted', message: res.message });
      setDeleteTarget(null);
      await fetchAssessments();
    } catch (e) {
      addToast({ type: 'error', title: 'Delete failed', message: getApiError(e) });
    } finally {
      setDeleting(false);
    }
  };

  const handleViewDetails = async (assessment: Assessment, tab: Tab = 'overview') => {
    setDetailAssessment(null);
    setDetailTab(tab);
    setArtifacts([]);
    setSelectedArtifact(null);
    setFiles([]);
    setFileContent(null);
    setReports([]);
    setLoadingDetail(true);
    setLoadingArtifacts(false);
    setLoadingReports(false);
    try {
      const res = await getAssessmentSummary(assessment.id);
      setDetailAssessment(res.data);
    } catch (e) {
      addToast({ type: 'error', title: 'Failed to load details', message: getApiError(e) });
      setDetailAssessment(null);
    } finally {
      setLoadingDetail(false);
    }
  };

  const closeDetailsModal = () => {
    setDetailAssessment(null);
    setArtifacts([]);
    setFiles([]);
    setFileContent(null);
  };

  const handleTabChange = (tab: Tab) => {
    setDetailTab(tab);
    if (tab === 'artifacts' && artifacts.length === 0 && !loadingArtifacts) {
      loadArtifacts();
    }
    if (tab === 'reports' && reports.length === 0 && !loadingReports) {
      loadReports();
    }
  };

  const loadArtifacts = async () => {
    if (!detailAssessment) return;
    setLoadingArtifacts(true);
    try {
      const res = await getArtifacts(detailAssessment.id, undefined, 1, 100);
      setArtifacts(res.data);
    } catch {
      setArtifacts([]);
    } finally {
      setLoadingArtifacts(false);
    }
  };

  const loadReports = async () => {
    if (!detailAssessment) return;
    setLoadingReports(true);
    try {
      const data = await getReports({ assessmentId: detailAssessment.id });
      setReports(Array.isArray(data) ? data : []);
    } catch {
      setReports([]);
    } finally {
      setLoadingReports(false);
    }
  };

  const handleViewFiles = async (artifact: Artifact) => {
    setSelectedArtifact(artifact);
    setFileContent(null);
    setLoadingFiles(true);
    try {
      setFiles(await getArtifactFiles(artifact.id));
    } catch {
      setFiles([]);
    } finally {
      setLoadingFiles(false);
    }
  };

  const handleViewFile = async (filename: string) => {
    if (!selectedArtifact) return;
    setLoadingContent(true);
    try {
      setFileContent(await downloadArtifactFile(selectedArtifact.id, filename));
    } catch {
      setFileContent(null);
    } finally {
      setLoadingContent(false);
    }
  };

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

  const handleGenerateReport = async () => {
    if (!detailAssessment) return;
    setGenerating(true);
    try {
      const res = await generateReport(reportType, reportFormat, detailAssessment.id);
      addToast({ type: 'success', title: res.message || 'Report generated' });
      await loadReports();
      await fetchAssessments();
    } catch (e) {
      addToast({ type: 'error', title: 'Report generation failed', message: getApiError(e) });
    } finally {
      setGenerating(false);
    }
  };

  const handleCleanup = async () => {
    if (!deletePreset) return;
    if (deletePreset === 'custom' && (!deleteFrom || !deleteTo)) {
      setError('Custom deletion requires both From and To dates');
      setShowDeleteConfirm(false);
      return;
    }
    setDeleting(true);
    try {
      const params: Record<string, string> = { preset: deletePreset };
      if (deletePreset === 'custom') {
        params.from_date = new Date(deleteFrom).toISOString();
        params.to_date = new Date(deleteTo).toISOString();
      }
      await apiClient.delete('/history/cleanup', { params });
      setShowDeleteConfirm(false);
      setDeletePreset('');
      setDeleteFrom('');
      setDeleteTo('');
      await fetchAssessments();
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setDeleting(false);
    }
  };

  const clearFilters = () => {
    setStatusFilter('');
    setScanTypeFilter('');
    setSearchInput('');
    setSearch('');
    setTargetFilter('');
    setDateFrom('');
    setDateTo('');
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h1 className="text-2xl font-bold text-surface-900 dark:text-surface-100">Assessment History</h1>
        <Button size="sm" variant="secondary" onClick={fetchAssessments} loading={loading}>
          Refresh
        </Button>
      </div>

      <Card>
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3 items-end">
          <div className="md:col-span-3 lg:col-span-2">
            <label className="block text-xs font-medium text-surface-500 mb-1">Search</label>
            <input
              type="text"
              placeholder="Search name or target..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="input w-full text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-surface-500 mb-1">Status</label>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="input w-full text-sm">
              <option value="">All</option>
              {STATUS_OPTIONS.filter(Boolean).map((s) => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-surface-500 mb-1">Type</label>
            <select value={scanTypeFilter} onChange={(e) => setScanTypeFilter(e.target.value)} className="input w-full text-sm">
              <option value="">All Types</option>
              {SCAN_TYPE_OPTIONS.filter(Boolean).map((s) => (
                <option key={s} value={s}>{SCAN_TYPE_LABELS[s] || s}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-surface-500 mb-1">Target / IP</label>
            <input
              type="text"
              placeholder="Filter target..."
              value={targetFilter}
              onChange={(e) => setTargetFilter(e.target.value)}
              className="input w-full text-sm"
            />
          </div>
          <div className="flex gap-3">
            <div className="flex-1">
              <label className="block text-xs font-medium text-surface-500 mb-1">From</label>
              <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} className="input w-full text-sm" />
            </div>
            <div className="flex-1">
              <label className="block text-xs font-medium text-surface-500 mb-1">To</label>
              <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} className="input w-full text-sm" />
            </div>
          </div>
        </div>
        <div className="mt-3 flex justify-end">
          <Button variant="ghost" size="sm" onClick={clearFilters}>Clear filters</Button>
        </div>
      </Card>

      {loading && <LoadingSpinner />}

      {error && (
        <Card><div className="p-4 text-center text-red-600">{error}</div></Card>
      )}

      {!loading && !error && assessments.length === 0 && (
        <Card><div className="p-4 text-center text-surface-500">No assessments found. Run an assessment first.</div></Card>
      )}

      {!loading && !error && assessments.length > 0 && (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-200 dark:border-surface-700">
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Name</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Type</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Target</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Severity</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Progress</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Duration</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Created</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Actions</th>
                </tr>
              </thead>
              <tbody>
                {assessments.map((a) => (
                  <tr key={a.id} className="border-b border-surface-100 dark:border-surface-800 hover:bg-surface-50 dark:hover:bg-surface-800/50">
                    <td className="py-3 px-4">
                      <button className="text-surface-900 dark:text-surface-100 font-medium hover:text-primary-600 text-left" onClick={() => handleViewDetails(a)}>
                        {a.name}
                      </button>
                    </td>
                    <td className="py-3 px-4"><Badge variant={statusColor(a.status)}>{a.status}</Badge></td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400">{SCAN_TYPE_LABELS[a.scan_type] || a.scan_type}</td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400 font-mono">{a.target || '-'}</td>
                    <td className="py-3 px-4"><SeverityChips counts={a.severity_counts ?? {}} /></td>
                    <td className="py-3 px-4 min-w-[110px]">
                      <ProgressBar
                        value={a.progress_percent ?? 0}
                        color={progressColor(a.status)}
                        size="sm"
                        showLabel
                      />
                    </td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400 whitespace-nowrap">
                      {formatDuration(a.started_at, a.completed_at, a.duration_seconds)}
                    </td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400 text-xs whitespace-nowrap">
                      {a.created_at ? new Date(a.created_at).toLocaleString() : '-'}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <Button variant="primary" size="sm" onClick={() => handleViewDetails(a)}>Details</Button>
                        <div className="relative">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setOpenMenuId(openMenuId === a.id ? null : a.id)}
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z" />
                            </svg>
                          </Button>
                          {openMenuId === a.id && (
                            <>
                              <div className="fixed inset-0 z-10" onClick={() => setOpenMenuId(null)} />
                              <div className="absolute right-0 z-20 mt-1 w-48 rounded-lg border border-surface-200 dark:border-surface-700 bg-white dark:bg-surface-800 shadow-xl py-1">
                                {a.status === 'draft' && (
                                  <MenuButton
                                    onClick={() => { setOpenMenuId(null); handleStartDraft(a); }}
                                    disabled={startingId === a.id}
                                  >
                                    {startingId === a.id ? 'Starting...' : '▶ Start Assessment'}
                                  </MenuButton>
                                )}
                                {a.status !== 'draft' && (
                                  <MenuButton onClick={() => { setOpenMenuId(null); handleViewDetails(a, 'reports'); }}>
                                    📄 Download Report
                                  </MenuButton>
                                )}
                                {a.status !== 'draft' && (
                                  <MenuButton onClick={() => { setOpenMenuId(null); handleRestore(a); }}>
                                    ▶ Restore Assessment
                                  </MenuButton>
                                )}
                                <MenuButton
                                  onClick={() => { setOpenMenuId(null); handleClone(a); }}
                                  disabled={cloningId === a.id}
                                >
                                  {cloningId === a.id ? 'Cloning...' : '🪄 Clone Assessment'}
                                </MenuButton>
                                <div className="border-t border-surface-200 dark:border-surface-700 my-1" />
                                <MenuButton danger onClick={() => { setOpenMenuId(null); setDeleteTarget(a); }}>
                                  🗑 Delete Assessment
                                </MenuButton>
                              </div>
                            </>
                          )}
                        </div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex justify-between items-center px-4 py-3 border-t border-surface-200 dark:border-surface-700">
            <span className="text-sm text-surface-500">
              {assessments.length} assessment{assessments.length === 1 ? '' : 's'}
              {hasActive && <span className="ml-2 text-primary-500">auto-refreshing...</span>}
            </span>
          </div>
        </Card>
      )}

      {isAdmin && (
        <Card title="Delete History">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-[200px]">
              <label className="block text-xs font-medium text-surface-500 mb-1">Preset</label>
              <select value={deletePreset} onChange={(e) => setDeletePreset(e.target.value)} className="input w-full text-sm">
                <option value="">Select time range...</option>
                {DELETE_PRESETS.map((p) => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
            </div>
            {deletePreset === 'custom' && (
              <>
                <div>
                  <label className="block text-xs font-medium text-surface-500 mb-1">From</label>
                  <input type="date" value={deleteFrom} onChange={(e) => setDeleteFrom(e.target.value)} className="input w-full text-sm" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-surface-500 mb-1">To</label>
                  <input type="date" value={deleteTo} onChange={(e) => setDeleteTo(e.target.value)} className="input w-full text-sm" />
                </div>
              </>
            )}
            <Button variant="danger" disabled={!deletePreset || (deletePreset === 'custom' && (!deleteFrom || !deleteTo))} onClick={() => setShowDeleteConfirm(true)}>
              Delete
            </Button>
          </div>
        </Card>
      )}

      {deleteTarget && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-surface-900 rounded-xl shadow-2xl max-w-md w-full p-6">
            <h3 className="text-lg font-semibold text-surface-900 dark:text-surface-100 mb-2">Delete Assessment</h3>
            <p className="text-sm text-surface-500 mb-2">
              You are about to permanently delete <span className="font-semibold text-surface-800 dark:text-surface-200">{deleteTarget.name}</span>.
            </p>
            <p className="text-sm text-critical bg-critical/10 rounded-lg p-3 mb-6">
              This will also remove all associated reports, artifacts, packet captures, hosts and findings. This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <Button variant="ghost" onClick={() => setDeleteTarget(null)} disabled={deleting}>Cancel</Button>
              <Button variant="danger" onClick={handleDelete} disabled={deleting}>
                {deleting ? 'Deleting...' : 'Delete'}
              </Button>
            </div>
          </div>
        </div>
      )}

      {detailAssessment && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-surface-900 rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-surface-200 dark:border-surface-700">
              <div className="min-w-0">
                <div className="flex items-center gap-3 flex-wrap">
                  <h3 className="text-lg font-semibold text-surface-900 dark:text-surface-100 truncate">
                    {detailAssessment.name}
                  </h3>
                  <Badge variant={statusColor(detailAssessment.status)}>{detailAssessment.status}</Badge>
                </div>
                <p className="text-sm text-surface-400 mt-0.5 font-mono">{detailAssessment.target}</p>
              </div>
              <div className="flex items-center gap-2">
                {detailAssessment.status === 'draft' ? (
                  <Button variant="primary" size="sm" onClick={() => { closeDetailsModal(); handleStartDraft({ id: detailAssessment.id, name: detailAssessment.name, status: detailAssessment.status } as Assessment); }}>
                    Start Assessment
                  </Button>
                ) : (
                  <Button variant="ghost" size="sm" onClick={() => handleRestore({ id: detailAssessment.id, name: detailAssessment.name, status: detailAssessment.status } as Assessment)}>
                    Restore
                  </Button>
                )}
                <Button variant="ghost" size="sm" onClick={closeDetailsModal}>Close</Button>
              </div>
            </div>

            <div className="flex border-b border-surface-200 dark:border-surface-700 px-4 gap-1">
              {(['overview', 'progress', 'reports', 'artifacts'] as Tab[]).map((tab) => (
                <button
                  key={tab}
                  onClick={() => handleTabChange(tab)}
                  className={`px-4 py-2.5 text-sm font-medium capitalize border-b-2 -mb-px transition-colors ${
                    detailTab === tab
                      ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                      : 'border-transparent text-surface-500 hover:text-surface-700 dark:hover:text-surface-300'
                  }`}
                >
                  {tab}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-y-auto">
              {loadingDetail && <div className="p-8"><LoadingSpinner /></div>}

              {!loadingDetail && detailTab === 'overview' && (
                <div className="p-6 space-y-6">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <Stat label="Duration" value={detailAssessment.duration_seconds !== null && detailAssessment.duration_seconds !== undefined ? formatSeconds(detailAssessment.duration_seconds) : '-'} />
                    <Stat label="Hosts" value={String(detailAssessment.hosts_count)} />
                    <Stat label="Open Ports" value={String(detailAssessment.ports_count)} />
                    <Stat label="Services" value={String(detailAssessment.services_count)} />
                    <Stat label="Vulnerabilities" value={String(detailAssessment.total_vulnerabilities)} />
                    <Stat label="Exploits" value={String(detailAssessment.exploits_count)} />
                    <Stat label="Reports" value={String(detailAssessment.reports_count)} />
                    <Stat label="Captures" value={String(detailAssessment.captures_count)} />
                  </div>

                  <div>
                    <h4 className="text-sm font-medium text-surface-600 dark:text-surface-400 mb-3">Severity Summary</h4>
                    <SeveritySummary
                      counts={detailAssessment.severity_counts}
                      total={detailAssessment.total_vulnerabilities}
                    />
                  </div>

                  {detailAssessment.error_message && (
                    <div className="p-3 rounded-lg bg-critical/10 text-critical text-sm">
                      {detailAssessment.error_message}
                    </div>
                  )}
                </div>
              )}

              {!loadingDetail && detailTab === 'progress' && (
                <div className="p-6 space-y-4">
                  <AssessmentProgress
                    progress={detailAssessment.progress}
                    status={detailAssessment.status}
                    overallPercent={detailAssessment.progress_percent}
                  />
                </div>
              )}

              {!loadingDetail && detailTab === 'reports' && (
                <div className="p-6 space-y-4">
                  <div className="flex flex-wrap items-end gap-3">
                    <div>
                      <label className="block text-xs font-medium text-surface-500 mb-1">Type</label>
                      <select value={reportType} onChange={(e) => setReportType(e.target.value)} className="input text-sm">
                        <option value="executive">Executive</option>
                        <option value="technical">Technical</option>
                        <option value="compliance">Compliance</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-surface-500 mb-1">Format</label>
                      <select value={reportFormat} onChange={(e) => setReportFormat(e.target.value)} className="input text-sm">
                        <option value="json">JSON</option>
                        <option value="html">HTML</option>
                        <option value="pdf">PDF</option>
                      </select>
                    </div>
                    <Button size="sm" onClick={handleGenerateReport} loading={generating}>Generate Report</Button>
                  </div>

                  {loadingReports && <div className="py-4"><LoadingSpinner /></div>}
                  {!loadingReports && (
                    <ReportList
                      reports={reports}
                      downloadingId={downloadingId}
                      onDownload={handleDownloadReport}
                    />
                  )}
                </div>
              )}

              {!loadingDetail && detailTab === 'artifacts' && (
                <div className="flex min-h-[300px]">
                  <div className="w-64 border-r border-surface-200 dark:border-surface-700 p-4 overflow-y-auto">
                    <h4 className="text-sm font-medium text-surface-500 mb-3">Stages</h4>
                    {loadingArtifacts && <LoadingSpinner />}
                    {!loadingArtifacts && artifacts.length === 0 && (
                      <p className="text-sm text-surface-400">No artifacts found.</p>
                    )}
                    {artifacts.map((art) => (
                      <button
                        key={art.id}
                        onClick={() => handleViewFiles(art)}
                        className={`w-full text-left px-3 py-2 rounded-lg text-sm mb-1 transition-colors ${
                          selectedArtifact?.id === art.id
                            ? 'bg-primary-50 dark:bg-primary-950/50 text-primary-700 dark:text-primary-300'
                            : 'text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800'
                        }`}
                      >
                        <div className="font-medium truncate">{STAGE_LABELS[art.stage_name] || art.stage_name}</div>
                        <div className="text-xs text-surface-400">{art.status}</div>
                      </button>
                    ))}
                  </div>
                  <div className="flex-1 p-4 overflow-y-auto">
                    {loadingFiles && <LoadingSpinner />}
                    {!loadingFiles && selectedArtifact && files.length === 0 && (
                      <p className="text-sm text-surface-400">No files for this stage</p>
                    )}
                    {!loadingFiles && selectedArtifact && files.length > 0 && (
                      <div>
                        <h4 className="text-sm font-medium text-surface-700 dark:text-surface-300 mb-3">Files</h4>
                        <div className="space-y-2">
                          {files.map((f) => (
                            <button
                              key={f.filename}
                              onClick={() => handleViewFile(f.filename)}
                              className="w-full text-left px-3 py-2 rounded-lg text-sm bg-surface-50 dark:bg-surface-950 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800"
                            >
                              <div className="font-medium text-surface-800 dark:text-surface-200 truncate">{f.filename}</div>
                              <div className="text-xs text-surface-400">{(f.size / 1024).toFixed(1)} KB</div>
                            </button>
                          ))}
                        </div>
                        {loadingContent && <div className="mt-3"><LoadingSpinner /></div>}
                        {!loadingContent && fileContent && (
                          <pre className="mt-3 bg-surface-50 dark:bg-surface-950 p-4 rounded-lg overflow-x-auto text-xs font-mono text-surface-800 dark:text-surface-200 max-h-72 overflow-y-auto whitespace-pre-wrap">
                            {fileContent.content}
                          </pre>
                        )}
                      </div>
                    )}
                    {!loadingFiles && !selectedArtifact && (
                      <p className="text-sm text-surface-400">Select a stage to view its artifacts</p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-surface-900 rounded-xl shadow-2xl max-w-md w-full p-6">
            <h3 className="text-lg font-semibold text-surface-900 dark:text-surface-100 mb-2">Confirm Deletion</h3>
            <p className="text-sm text-surface-500 mb-6">
              This will permanently delete all assessment data{deletePreset === 'all' ? '' : ' for the selected period'}, including reports, artifacts and captures. This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <Button variant="ghost" onClick={() => { setShowDeleteConfirm(false); setDeleting(false); }} disabled={deleting}>Cancel</Button>
              <Button variant="danger" onClick={handleCleanup} disabled={deleting}>
                {deleting ? 'Deleting...' : 'Delete'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function MenuButton({
  children,
  onClick,
  disabled,
  danger,
}: {
  children: React.ReactNode;
  onClick: () => void;
  disabled?: boolean;
  danger?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`w-full text-left px-4 py-2 text-sm transition-colors disabled:opacity-50 ${
        danger
          ? 'text-critical hover:bg-critical/10'
          : 'text-surface-700 dark:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-700'
      }`}
    >
      {children}
    </button>
  );
}
