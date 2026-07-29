import { useCallback, useEffect, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import type { Artifact, ArtifactContent, ArtifactFile } from '../types/artifact';
import { getArtifactFiles, getArtifacts, downloadArtifactFile } from '../services/artifactService';

const STAGE_LABELS: Record<string, string> = {
  host_discovery: 'Host Discovery',
  port_scan: 'Port Scan',
  service_intelligence: 'Service Intelligence',
  vulnerability_assessment: 'Vulnerability Assessment',
};

function statusColor(status: string): 'success' | 'warning' | 'danger' | 'info' | 'default' {
  switch (status) {
    case 'completed': return 'success';
    case 'failed': return 'danger';
    case 'running': return 'info';
    default: return 'default';
  }
}

function formatDuration(seconds: number | null): string {
  if (seconds === null) return '-';
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs.toFixed(0)}s`;
}

export function History() {
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [stageFilter, setStageFilter] = useState('');
  const perPage = 20;

  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null);
  const [files, setFiles] = useState<ArtifactFile[]>([]);
  const [fileContent, setFileContent] = useState<ArtifactContent | null>(null);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [loadingContent, setLoadingContent] = useState(false);

  const fetchArtifacts = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getArtifacts(
        undefined,
        stageFilter || undefined,
        page,
        perPage,
      );
      setArtifacts(res.data);
      setTotal(res.pagination.total);
      setTotalPages(res.pagination.total_pages);
    } catch {
      setError('Failed to load assessment history.');
    } finally {
      setLoading(false);
    }
  }, [stageFilter, page]);

  useEffect(() => { fetchArtifacts(); }, [fetchArtifacts]);

  useEffect(() => { setPage(1); }, [stageFilter]);

  const handleViewFiles = async (artifact: Artifact) => {
    setSelectedArtifact(artifact);
    setFileContent(null);
    setLoadingFiles(true);
    try {
      const res = await getArtifactFiles(artifact.id);
      setFiles(res);
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
      const res = await downloadArtifactFile(selectedArtifact.id, filename);
      setFileContent(res);
    } catch {
      setFileContent(null);
    } finally {
      setLoadingContent(false);
    }
  };

  const closeDetail = () => {
    setSelectedArtifact(null);
    setFiles([]);
    setFileContent(null);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-surface-900 dark:text-surface-100">
          Assessment History
        </h1>
      </div>

      <div className="flex gap-3 items-center">
        <select
          value={stageFilter}
          onChange={(e) => setStageFilter(e.target.value)}
          className="px-3 py-2 border border-surface-300 dark:border-surface-600 rounded-lg bg-white dark:bg-surface-800 text-surface-900 dark:text-surface-100"
        >
          <option value="">All Stages</option>
          <option value="host_discovery">Host Discovery</option>
          <option value="port_scan">Port Scan</option>
          <option value="service_intelligence">Service Intelligence</option>
          <option value="vulnerability_assessment">Vulnerability Assessment</option>
        </select>
      </div>

      {loading && <LoadingSpinner />}

      {error && (
        <Card>
          <div className="p-4 text-center text-red-600">{error}</div>
        </Card>
      )}

      {!loading && !error && artifacts.length === 0 && (
        <Card>
          <div className="p-4 text-center text-surface-500">No assessment history found.</div>
        </Card>
      )}

      {!loading && !error && artifacts.length > 0 && (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-200 dark:border-surface-700">
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Stage</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Target</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Scanner</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Duration</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Started</th>
                  <th className="text-left py-3 px-4 font-medium text-surface-600 dark:text-surface-400">Actions</th>
                </tr>
              </thead>
              <tbody>
                {artifacts.map((a) => (
                  <tr key={a.id} className="border-b border-surface-100 dark:border-surface-800 hover:bg-surface-50 dark:hover:bg-surface-800/50">
                    <td className="py-3 px-4 text-surface-900 dark:text-surface-100">
                      {STAGE_LABELS[a.stage_name] || a.stage_name}
                    </td>
                    <td className="py-3 px-4">
                      <Badge variant={statusColor(a.status)}>{a.status}</Badge>
                    </td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400 font-mono">{a.target || '-'}</td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400">{a.scanner_name || '-'}</td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400">{formatDuration(a.duration)}</td>
                    <td className="py-3 px-4 text-surface-600 dark:text-surface-400 text-xs">
                      {a.start_time ? new Date(a.start_time).toLocaleString() : '-'}
                    </td>
                    <td className="py-3 px-4">
                      <Button variant="ghost" size="sm" onClick={() => handleViewFiles(a)}>
                        View
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex justify-between items-center px-4 py-3 border-t border-surface-200 dark:border-surface-700">
              <span className="text-sm text-surface-500">{total} total artifacts</span>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <span className="text-sm text-surface-500 self-center">Page {page} of {totalPages}</span>
                <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
          )}
        </Card>
      )}

      {selectedArtifact && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-white dark:bg-surface-900 rounded-xl shadow-2xl max-w-4xl w-full max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-surface-200 dark:border-surface-700">
              <h3 className="text-lg font-semibold text-surface-900 dark:text-surface-100">
                {STAGE_LABELS[selectedArtifact.stage_name] || selectedArtifact.stage_name} - Artifacts
              </h3>
              <Button variant="ghost" size="sm" onClick={closeDetail}>Close</Button>
            </div>

            <div className="flex flex-1 min-h-0">
              <div className="w-64 border-r border-surface-200 dark:border-surface-700 p-4 overflow-y-auto">
                <h4 className="text-sm font-medium text-surface-500 mb-3">Files</h4>
                {loadingFiles && <LoadingSpinner />}
                {!loadingFiles && files.length === 0 && (
                  <p className="text-sm text-surface-400">No files found</p>
                )}
                {!loadingFiles && files.map((f) => (
                  <button
                    key={f.filename}
                    onClick={() => handleViewFile(f.filename)}
                    className={`w-full text-left px-3 py-2 rounded-lg text-sm mb-1 transition-colors ${
                      fileContent?.filename === f.filename
                        ? 'bg-primary-50 dark:bg-primary-950/50 text-primary-700 dark:text-primary-300'
                        : 'text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800'
                    }`}
                  >
                    <div className="font-medium truncate">{f.filename}</div>
                    <div className="text-xs text-surface-400">{(f.size / 1024).toFixed(1)} KB</div>
                  </button>
                ))}
              </div>

              <div className="flex-1 p-4 overflow-y-auto">
                {loadingContent && <LoadingSpinner />}
                {!loadingContent && fileContent && (
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-sm font-medium text-surface-700 dark:text-surface-300">{fileContent.filename}</h4>
                      <Badge variant="default">{fileContent.content_type}</Badge>
                    </div>
                    <pre className="bg-surface-50 dark:bg-surface-950 p-4 rounded-lg overflow-x-auto text-xs font-mono text-surface-800 dark:text-surface-200 max-h-96 overflow-y-auto whitespace-pre-wrap">
                      {fileContent.content}
                    </pre>
                  </div>
                )}
                {!loadingContent && !fileContent && (
                  <p className="text-sm text-surface-400">Select a file to view its contents</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
