import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import type { Artifact, ArtifactContent, ArtifactFile } from '../types/artifact';
import type { Assessment } from '../types/assessment';
import { getArtifactFiles, getArtifacts, downloadArtifactFile } from '../services/artifactService';
import { getAssessments } from '../services/assessmentService';
import apiClient from '../services/api';
import { getApiError } from '../services/api';
import { setActiveAssessment, useAssessmentChangeTick } from '../services/assessmentStore';

const SCAN_TYPE_LABELS: Record<string, string> = {
  full_assessment: 'Full Assessment',
  host_discovery: 'Host Discovery',
  port_scan: 'Port Scan',
  service_enum: 'Service Intelligence',
  vuln_scan: 'Vulnerability Scan',
};

const SCAN_TYPE_OPTIONS = ['', 'full_assessment', 'host_discovery', 'port_scan', 'service_enum', 'vuln_scan'];

const STAGE_LABELS: Record<string, string> = {
  host_discovery: 'Host Discovery',
  port_scan: 'Port Scan',
  service_intelligence: 'Service Intelligence',
  vulnerability_assessment: 'Vulnerability Assessment',
  cve_intelligence: 'CVE Intelligence',
  exploit_verification: 'Exploit Verification',
};

const STATUS_OPTIONS = ['', 'completed', 'failed', 'running', 'pending', 'cancelled'];

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

function statusColor(status: string): 'success' | 'warning' | 'danger' | 'info' | 'default' {
  switch (status) {
    case 'completed': return 'success';
    case 'failed': return 'danger';
    case 'running': return 'info';
    case 'cancelled': return 'warning';
    default: return 'default';
  }
}

function formatDuration(startedAt: string | null, completedAt: string | null): string {
  if (!startedAt || !completedAt) return '-';
  const seconds = (new Date(completedAt).getTime() - new Date(startedAt).getTime()) / 1000;
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs.toFixed(0)}s`;
}

export function History() {
  const navigate = useNavigate();

  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [scanTypeFilter, setScanTypeFilter] = useState('');
  const [targetSearch, setTargetSearch] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  const [selectedAssessment, setSelectedAssessment] = useState<Assessment | null>(null);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null);
  const [files, setFiles] = useState<ArtifactFile[]>([]);
  const [fileContent, setFileContent] = useState<ArtifactContent | null>(null);
  const [loadingArtifacts, setLoadingArtifacts] = useState(false);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [loadingContent, setLoadingContent] = useState(false);

  const [deletePreset, setDeletePreset] = useState('');
  const [deleteFrom, setDeleteFrom] = useState('');
  const [deleteTo, setDeleteTo] = useState('');
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const tick = useAssessmentChangeTick();

  const fetchAssessments = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAssessments(statusFilter || undefined, scanTypeFilter || undefined, 1, 100);
      setAssessments(res.data);
    } catch {
      setError('Failed to load assessment history.');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, scanTypeFilter, tick]);

  useEffect(() => { fetchAssessments(); }, [fetchAssessments]);

  const filtered = useMemo(() => {
    let list = assessments;
    if (targetSearch) { const q = targetSearch.toLowerCase(); list = list.filter((a) => a.target?.toLowerCase().includes(q)); }
    if (dateFrom) { const from = new Date(dateFrom).getTime(); list = list.filter((a) => new Date(a.created_at).getTime() >= from); }
    if (dateTo) { const to = new Date(dateTo).getTime() + 86400000; list = list.filter((a) => new Date(a.created_at).getTime() <= to); }
    return list;
  }, [assessments, targetSearch, dateFrom, dateTo]);

  const handleRestore = (assessment: Assessment) => {
    setActiveAssessment(assessment.id, assessment.name);
    navigate('/');
  };

  const handleViewArtifacts = async (assessment: Assessment) => {
    setSelectedAssessment(assessment);
    setSelectedArtifact(null);
    setFileContent(null);
    setLoadingArtifacts(true);
    setError(null);
    try {
      const res = await getArtifacts(assessment.id, undefined, 1, 100);
      setArtifacts(res.data);
    } catch {
      setArtifacts([]);
    } finally {
      setLoadingArtifacts(false);
    }
  };

  const closeArtifactsModal = () => {
    setSelectedAssessment(null);
    setSelectedArtifact(null);
    setArtifacts([]);
    setFiles([]);
    setFileContent(null);
  };

  const handleViewFiles = async (artifact: Artifact) => {
    setSelectedArtifact(artifact);
    setFileContent(null);
    setLoadingFiles(true);
    try { setFiles(await getArtifactFiles(artifact.id)); } catch { setFiles([]); }
    finally { setLoadingFiles(false); }
  };

  const handleViewFile = async (filename: string) => {
    if (!selectedArtifact) return;
    setLoadingContent(true);
    try { setFileContent(await downloadArtifactFile(selectedArtifact.id, filename)); } catch { setFileContent(null); }
    finally { setLoadingContent(false); }
  };

  const handleDelete = async () => {
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-surface-900 dark:text-surface-100">Assessment History</h1>
      </div>

      <Card>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          <div>
            <label className="block text-xs font-medium text-surface-500 mb-1">From</label>
            <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} className="input w-full text-sm" />
          </div>
          <div>
            <label className="block text-xs font-medium text-surface-500 mb-1">To</label>
            <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} className="input w-full text-sm" />
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
            <input type="text" placeholder="Search target..." value={targetSearch} onChange={(e) => setTargetSearch(e.target.value)} className="input w-full text-sm" />
          </div>
        </div>
      </Card>

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

      {loading && <LoadingSpinner />}

      {error && (
        <Card><div className="p-4 text-center text-red-600">{error}</div></Card>
      )}

      {!loading && !error && filtered.length === 0 && (
        <Card><div className="p-4 text-center text-surface-500">No assessments found. Run an assessment first.</div></Card>
      )}

      {!loading && !error && filtered.length > 0 && (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-200 dark:border-surface-700">
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Name</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Type</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Target</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Duration</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Created</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => (
                  <tr key={a.id} className="border-b border-surface-100 dark:border-surface-800 hover:bg-surface-50 dark:hover:bg-surface-800/50">
                    <td className="py-3 px-4 text-surface-900 dark:text-surface-100">{a.name}</td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400">{SCAN_TYPE_LABELS[a.scan_type] || a.scan_type}</td>
                    <td className="py-3 px-4"><Badge variant={statusColor(a.status)}>{a.status}</Badge></td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400 font-mono">{a.target || '-'}</td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400">{formatDuration(a.started_at, a.completed_at)}</td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400 text-xs">
                      {a.created_at ? new Date(a.created_at).toLocaleString() : '-'}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex gap-2">
                        <Button variant="primary" size="sm" onClick={() => handleRestore(a)}>Restore</Button>
                        <Button variant="ghost" size="sm" onClick={() => handleViewArtifacts(a)}>View</Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex justify-between items-center px-4 py-3 border-t border-surface-200 dark:border-surface-700">
            <span className="text-sm text-surface-500">{filtered.length} assessment{filtered.length === 1 ? '' : 's'}</span>
          </div>
        </Card>
      )}

      {selectedAssessment && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-surface-900 rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-surface-200 dark:border-surface-700">
              <h3 className="text-lg font-semibold text-surface-900 dark:text-surface-100">
                {selectedAssessment.name} - Stage Artifacts
              </h3>
              <Button variant="ghost" size="sm" onClick={closeArtifactsModal}>Close</Button>
            </div>
            {loadingArtifacts && <div className="p-4"><LoadingSpinner /></div>}
            {!loadingArtifacts && artifacts.length === 0 && (
              <div className="p-4 text-center text-surface-500">No artifacts found for this assessment.</div>
            )}
            {!loadingArtifacts && artifacts.length > 0 && (
              <div className="flex flex-1 min-h-0">
                <div className="w-64 border-r border-surface-200 dark:border-surface-700 p-4 overflow-y-auto">
                  <h4 className="text-sm font-medium text-surface-500 mb-3">Stages</h4>
                  {artifacts.map((art) => (
                    <button key={art.id} onClick={() => handleViewFiles(art)}
                      className={`w-full text-left px-3 py-2 rounded-lg text-sm mb-1 transition-colors ${selectedArtifact?.id === art.id ? 'bg-primary-50 dark:bg-primary-950/50 text-primary-700 dark:text-primary-300' : 'text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800'}`}>
                      <div className="font-medium truncate">{STAGE_LABELS[art.stage_name] || art.stage_name}</div>
                      <div className="text-xs text-surface-400">{art.status}</div>
                    </button>
                  ))}
                </div>
                <div className="flex-1 p-4 overflow-y-auto">
                  {loadingFiles && <LoadingSpinner />}
                  {!loadingFiles && selectedArtifact && files.length === 0 && <p className="text-sm text-surface-400">No files for this stage</p>}
                  {!loadingFiles && selectedArtifact && files.length > 0 && (
                    <div>
                      <h4 className="text-sm font-medium text-surface-700 dark:text-surface-300 mb-3">Files</h4>
                      <div className="space-y-2">
                        {files.map((f) => (
                          <button key={f.filename} onClick={() => handleViewFile(f.filename)}
                            className="w-full text-left px-3 py-2 rounded-lg text-sm bg-surface-50 dark:bg-surface-950 text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800">
                            <div className="font-medium text-surface-800 dark:text-surface-200 truncate">{f.filename}</div>
                            <div className="text-xs text-surface-400">{(f.size / 1024).toFixed(1)} KB</div>
                          </button>
                        ))}
                      </div>
                      {loadingContent && <div className="mt-3"><LoadingSpinner /></div>}
                      {!loadingContent && fileContent && (
                        <pre className="mt-3 bg-surface-50 dark:bg-surface-950 p-4 rounded-lg overflow-x-auto text-xs font-mono text-surface-800 dark:text-surface-200 max-h-72 overflow-y-auto whitespace-pre-wrap">{fileContent.content}</pre>
                      )}
                    </div>
                  )}
                  {!loadingFiles && !selectedArtifact && <p className="text-sm text-surface-400">Select a stage to view its artifacts</p>}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-surface-900 rounded-xl shadow-2xl max-w-md w-full p-6">
            <h3 className="text-lg font-semibold text-surface-900 dark:text-surface-100 mb-2">Confirm Deletion</h3>
            <p className="text-sm text-surface-500 mb-6">
              This will permanently delete all assessment data{deletePreset === 'all' ? '' : ` for the selected period`}. This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <Button variant="ghost" onClick={() => { setShowDeleteConfirm(false); setDeleting(false); }} disabled={deleting}>Cancel</Button>
              <Button variant="danger" onClick={handleDelete} disabled={deleting}>
                {deleting ? 'Deleting...' : 'Delete'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
