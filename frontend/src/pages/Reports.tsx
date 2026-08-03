import { useCallback, useEffect, useRef, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { Table, type Column } from '../components/ui/Table';
import { useToast } from '../hooks/useToast';
import { getApiError } from '../services/api';
import { getActiveAssessmentId, useAssessmentChangeTick } from '../services/assessmentStore';
import {
  deleteReport,
  downloadReport,
  generateReport,
  getReports,
  renameReport,
  type Report,
} from '../services/reportService';

const reportFormats = [
  { value: 'executive', label: 'Executive Summary', desc: 'High-level overview for management', icon: '📋' },
  { value: 'technical', label: 'Technical Report', desc: 'Detailed findings with evidence', icon: '🔬' },
  { value: 'compliance', label: 'Compliance Report', desc: 'Mapping to standards (CIS, NIST)', icon: '📋' },
];

const exportFormats = ['JSON', 'HTML', 'PDF'];

const TYPE_BADGE: Record<string, 'info' | 'warning' | 'success' | 'default'> = {
  Executive: 'info',
  Technical: 'warning',
  Compliance: 'success',
};

function TypeBadge({ type }: { type: string }) {
  return <Badge variant={TYPE_BADGE[type] ?? 'default'}>{type}</Badge>;
}

export function Reports() {
  const { addToast } = useToast();
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [generating, setGenerating] = useState(false);
  const [selectedType, setSelectedType] = useState('executive');
  const [selectedFormat, setSelectedFormat] = useState('JSON');
  const [renameTarget, setRenameTarget] = useState<Report | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Report | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const tick = useAssessmentChangeTick();

  const searchTimer = useRef<number | null>(null);

  useEffect(() => {
    if (searchTimer.current) window.clearTimeout(searchTimer.current);
    searchTimer.current = window.setTimeout(() => setSearch(searchInput.trim()), 350);
    return () => {
      if (searchTimer.current) window.clearTimeout(searchTimer.current);
    };
  }, [searchInput]);

  const fetchReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const data = await getReports({
        assessmentId,
        reportType: typeFilter || undefined,
        search: search || undefined,
        sortBy: 'created_at',
        sortOrder: 'desc',
      });
      setReports(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  }, [tick, search, typeFilter]);

  useEffect(() => { fetchReports(); }, [fetchReports]);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const res = await generateReport(selectedType, selectedFormat.toLowerCase(), assessmentId);
      addToast({
        type: 'success',
        title: res.message || 'Report generated successfully',
      });
      await fetchReports();
    } catch (e) {
      addToast({ type: 'error', title: 'Report generation failed', message: getApiError(e) });
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (report: Report) => {
    setBusyId(report.id);
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
      setBusyId(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      const res = await deleteReport(deleteTarget.id);
      addToast({
        type: 'success',
        title: `Report "${deleteTarget.title}" deleted`,
        message: res.message,
      });
      setReports((prev) => prev.filter((r) => r.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch (e) {
      addToast({ type: 'error', title: 'Delete failed', message: getApiError(e) });
      setDeleteTarget(null);
    } finally {
      setBusyId(null);
    }
  };

  const columns: Column<Report>[] = [
    {
      key: 'title',
      header: 'Title',
      render: (r) => (
        <div className="font-medium text-surface-900 dark:text-surface-100">{r.title}</div>
      ),
    },
    {
      key: 'type',
      header: 'Type',
      render: (r) => <TypeBadge type={r.type} />,
    },
    {
      key: 'format',
      header: 'Format',
      render: (r) => <span className="font-mono text-xs">{r.format}</span>,
    },
    {
      key: 'size',
      header: 'Size',
      render: (r) => <span className="text-surface-500">{r.size}</span>,
    },
    {
      key: 'date',
      header: 'Created',
      render: (r) => (
        <span className="text-surface-500">
          {r.date ? new Date(r.date).toLocaleString() : '-'}
        </span>
      ),
    },
    {
      key: 'assessment',
      header: 'Assessment',
      render: (r) => (
        <span className="text-xs text-surface-400">
          {r.assessment_id ? r.assessment_id.slice(0, 8) : '—'}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      render: (r) => (
        <div className="flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="sm"
            disabled={busyId !== null}
            onClick={() => handleDownload(r)}
          >
            {busyId === r.id ? 'Downloading…' : 'Download'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={busyId !== null}
            onClick={() => setRenameTarget(r)}
          >
            Rename
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="text-critical hover:bg-critical/10"
            disabled={busyId !== null}
            onClick={() => setDeleteTarget(r)}
          >
            Delete
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <Card title="Generate Report" subtitle="Create professional VAPT reports">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {reportFormats.map((rf) => (
            <div
              key={rf.value}
              className={`p-4 rounded-lg border cursor-pointer transition-colors ${selectedType === rf.value ? 'border-primary-500 bg-primary-50 dark:bg-primary-950/50' : 'border-surface-200 dark:border-surface-700 hover:border-primary-500'}`}
              onClick={() => setSelectedType(rf.value)}
            >
              <span className="text-2xl">{rf.icon}</span>
              <h4 className="font-medium text-surface-900 dark:text-surface-100 mt-2">{rf.label}</h4>
              <p className="text-xs text-surface-400 mt-1">{rf.desc}</p>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Export Format</label>
            <div className="flex gap-3">
              {exportFormats.map((fmt) => (
                <label key={fmt} className="flex items-center gap-1.5 cursor-pointer">
                  <input type="radio" name="format" checked={selectedFormat === fmt}
                    onChange={() => setSelectedFormat(fmt)} className="text-primary-500" />
                  <span className="text-sm text-surface-700 dark:text-surface-300">{fmt}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="flex items-end">
            <Button variant="primary" onClick={handleGenerate} disabled={generating} loading={generating}>
              {generating ? 'Generating...' : 'Generate Report'}
            </Button>
          </div>
        </div>
      </Card>

      <Card
        title="Generated Reports"
        subtitle={`${reports.length} report${reports.length === 1 ? '' : 's'}`}
        action={
          <Button variant="secondary" size="sm" onClick={fetchReports} disabled={loading}>
            Refresh
          </Button>
        }
      >
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <input
            className="input w-full max-w-xs"
            placeholder="Search report titles..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <select
            className="input w-auto"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            aria-label="Filter by report type"
          >
            <option value="">All Types</option>
            <option value="executive">Executive</option>
            <option value="technical">Technical</option>
            <option value="compliance">Compliance</option>
          </select>
          {error && <span className="text-sm text-critical">{error}</span>}
        </div>

        <Table
          columns={columns}
          data={reports}
          keyExtractor={(r) => r.id}
          loading={loading}
          emptyMessage={
            search || typeFilter
              ? 'No reports match the current search or filters'
              : 'No reports generated yet. Use the generator above to create one.'
          }
        />
      </Card>

      <RenameReportDialog
        report={renameTarget}
        onClose={() => setRenameTarget(null)}
        onRenamed={(updated) => {
          setRenameTarget(null);
          setReports((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
          addToast({ type: 'success', title: 'Report renamed successfully' });
        }}
      />

      <DeleteReportDialog
        report={deleteTarget}
        busy={busyId === deleteTarget?.id}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
      />
    </div>
  );
}

function RenameReportDialog({
  report,
  onClose,
  onRenamed,
}: {
  report: Report | null;
  onClose: () => void;
  onRenamed: (report: Report) => void;
}) {
  const { addToast } = useToast();
  const [title, setTitle] = useState('');
  const [titleError, setTitleError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (report) {
      setTitle(report.title);
      setTitleError(null);
    }
  }, [report]);

  const handleSubmit = async () => {
    if (!report) return;
    const trimmed = title.trim();
    if (!trimmed) {
      setTitleError('Report title cannot be empty');
      return;
    }
    if (trimmed.length > 255) {
      setTitleError('Report title is too long (max 255 characters)');
      return;
    }
    if (trimmed === report.title) {
      onClose();
      return;
    }
    setSubmitting(true);
    try {
      const updated = await renameReport(report.id, trimmed);
      onRenamed(updated);
    } catch (e) {
      addToast({ type: 'error', title: 'Rename failed', message: getApiError(e) });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={report !== null}
      onClose={onClose}
      title="Rename Report"
      size="sm"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button loading={submitting} onClick={handleSubmit}>
            Rename
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-surface-400">
          Renaming changes the report title only; the stored file is untouched.
        </p>
        <div>
          <label className="block text-sm font-medium mb-1">Title *</label>
          <input
            className="input w-full"
            value={title}
            onChange={(e) => {
              setTitle(e.target.value);
              setTitleError(null);
            }}
            maxLength={255}
            onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          />
          {titleError && <p className="mt-1 text-xs text-critical">{titleError}</p>}
        </div>
      </div>
    </Modal>
  );
}

function DeleteReportDialog({
  report,
  busy,
  onClose,
  onConfirm,
}: {
  report: Report | null;
  busy: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal
      open={report !== null}
      onClose={onClose}
      title="Delete Report"
      size="sm"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" loading={busy} onClick={onConfirm}>
            Delete
          </Button>
        </>
      }
    >
      {report && (
        <div className="space-y-3">
          <p className="text-sm text-surface-700 dark:text-surface-300">
            Are you sure you want to delete report <b>{report.title}</b>? The report file will be
            permanently removed from disk.
          </p>
          <p className="text-xs text-surface-400">
            Type: {report.type} | Format: {report.format} | Size: {report.size}
          </p>
        </div>
      )}
    </Modal>
  );
}
