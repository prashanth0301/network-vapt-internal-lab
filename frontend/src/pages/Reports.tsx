import { useCallback, useEffect, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { getApiError } from '../services/api';
import { getActiveAssessmentId, useAssessmentChangeTick } from '../services/assessmentStore';
import {
  downloadReport,
  generateReport,
  getReports,
  type Report,
} from '../services/reportService';

const reportFormats = [
  { value: 'executive', label: 'Executive Summary', desc: 'High-level overview for management', icon: '📋' },
  { value: 'technical', label: 'Technical Report', desc: 'Detailed findings with evidence', icon: '🔬' },
  { value: 'compliance', label: 'Compliance Report', desc: 'Mapping to standards (CIS, NIST)', icon: '📋' },
];

const exportFormats = ['JSON', 'HTML', 'PDF'];

export function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);
  const [selectedType, setSelectedType] = useState('executive');
  const [selectedFormat, setSelectedFormat] = useState('JSON');
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const tick = useAssessmentChangeTick();

  const fetchReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const data = await getReports(assessmentId);
      setReports(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  }, [tick]);

  useEffect(() => { fetchReports(); }, [fetchReports]);

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const res = await generateReport(selectedType, selectedFormat.toLowerCase(), assessmentId);
      setSuccessMessage(res.message || 'Report generated successfully');
      await fetchReports();
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (report: Report) => {
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
    } catch (e) {
      setError(getApiError(e));
    }
  };

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
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
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
            <Button variant="primary" onClick={handleGenerate} disabled={generating}>
              {generating ? 'Generating...' : 'Generate Report'}
            </Button>
          </div>
        </div>
        {error && (
          <div className="p-3 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">{error}</div>
        )}
        {successMessage && (
          <div className="p-3 text-success bg-success/10 rounded-lg border border-success/20 text-sm">{successMessage}</div>
        )}
      </Card>

      {loading ? (
        <LoadingSpinner size="md" text="Loading reports..." />
      ) : reports.length === 0 ? (
        <Card title="Generated Reports">
          <div className="text-center py-12 text-surface-400">
            <p className="text-lg font-medium mb-1">No reports generated yet</p>
            <p className="text-sm">Generate a report to see it listed here.</p>
          </div>
        </Card>
      ) : (
        <Card title="Generated Reports" subtitle={`${reports.length} reports`}>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-200 dark:border-surface-700">
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Title</th>
                  <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Type</th>
                  <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Format</th>
                  <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Size</th>
                  <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Date</th>
                  <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                {reports.map((report) => (
                  <tr key={report.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                    <td className="px-4 py-3 font-medium text-surface-900 dark:text-surface-100">{report.title}</td>
                    <td className="px-4 py-3 text-center">
                      <Badge variant={report.type === 'Executive' ? 'info' : 'default'}>{report.type}</Badge>
                    </td>
                    <td className="px-4 py-3 text-center font-mono text-xs">{report.format}</td>
                    <td className="px-4 py-3 text-right text-surface-500">{report.size}</td>
                    <td className="px-4 py-3 text-right text-surface-400">{report.date ? new Date(report.date).toLocaleDateString() : '-'}</td>
                    <td className="px-4 py-3 text-center">
                      <Button variant="ghost" size="sm" onClick={() => handleDownload(report)}>Download</Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
