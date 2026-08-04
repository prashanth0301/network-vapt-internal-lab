import { Button } from '../ui/Button';
import { LoadingSpinner } from '../ui/LoadingSpinner';
import type { Report } from '../../services/reportService';

interface ReportListProps {
  reports: Report[];
  loading?: boolean;
  downloadingId?: string | null;
  onDownload: (report: Report) => void;
  emptyMessage?: string;
}

export function ReportList({
  reports,
  loading = false,
  downloadingId = null,
  onDownload,
  emptyMessage = 'No reports for this assessment yet.',
}: ReportListProps) {
  if (loading) {
    return (
      <div className="py-4">
        <LoadingSpinner />
      </div>
    );
  }
  if (reports.length === 0) {
    return <p className="text-sm text-surface-400">{emptyMessage}</p>;
  }
  return (
    <div className="divide-y divide-surface-100 dark:divide-surface-800 border border-surface-200 dark:border-surface-700 rounded-lg">
      {reports.map((r) => (
        <div key={r.id} className="flex items-center justify-between px-4 py-3">
          <div className="min-w-0">
            <p className="text-sm font-medium text-surface-900 dark:text-surface-100 truncate">{r.title}</p>
            <p className="text-xs text-surface-400 mt-0.5">
              {r.type} · {r.format} · {r.size} · {r.date ? new Date(r.date).toLocaleString() : '-'}
            </p>
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => onDownload(r)}
            loading={downloadingId === r.id}
          >
            Download
          </Button>
        </div>
      ))}
    </div>
  );
}
