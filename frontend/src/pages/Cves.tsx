import { useCallback, useEffect, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { CVEDetailModal } from '../components/CVEDetailModal';
import type { CVE, CVEStatistics } from '../types/cve';
import { getCVEs, getCVEStatistics } from '../services/cveService';
import { getActiveAssessmentId, useAssessmentChangeTick } from '../services/assessmentStore';

const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];
const severityColors: Record<string, string> = {
  Critical: 'text-critical', High: 'text-high', Medium: 'text-medium', Low: 'text-low', Info: 'text-info',
};

function severityBadge(severity: string | null): 'danger' | 'warning' | 'info' | 'default' {
  switch (severity) {
    case 'Critical': return 'danger';
    case 'High': return 'warning';
    case 'Medium': return 'info';
    case 'Low': return 'info';
    default: return 'default';
  }
}

export function Cves() {
  const [cves, setCves] = useState<CVE[]>([]);
  const [stats, setStats] = useState<CVEStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [vendorFilter, setVendorFilter] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [sortBy, setSortBy] = useState('cvss_score');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [selectedCveId, setSelectedCveId] = useState<string | null>(null);
  const perPage = 20;
  const tick = useAssessmentChangeTick();

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const assessmentId = getActiveAssessmentId() ?? undefined;
      const [cvesRes, statsRes] = await Promise.all([
        getCVEs(
          severityFilter || undefined,
          vendorFilter || undefined,
          undefined,
          undefined,
          search || undefined,
          kevOnly,
          sortBy,
          sortOrder,
          page,
          perPage,
          assessmentId,
        ),
        getCVEStatistics(assessmentId),
      ]);
      setCves(cvesRes.data);
      setTotal(cvesRes.pagination.total);
      setTotalPages(cvesRes.pagination.total_pages);
      setStats(statsRes.data);
    } catch {
      setError('Failed to load CVE intelligence data.');
    } finally {
      setLoading(false);
    }
  }, [severityFilter, vendorFilter, search, kevOnly, sortBy, sortOrder, page, tick]);

  useEffect(() => { fetchData(); }, [fetchData]);

  useEffect(() => { setPage(1); }, [search, severityFilter, vendorFilter, kevOnly, sortBy, sortOrder]);

  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder((o) => (o === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  const sortIndicator = (field: string) => {
    if (sortBy !== field) return null;
    return sortOrder === 'asc' ? ' ▲' : ' ▼';
  };

  return (
    <div className="space-y-6">
      {stats && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {severityOrder.map((sev) => {
              const count = stats.severity_counts?.[sev] ?? 0;
              const pct = stats.total_cves > 0 ? Math.round((count / stats.total_cves) * 100) : 0;
              return (
                <Card key={sev} className="text-center">
                  <p className="text-xs font-medium uppercase text-surface-400 mb-1">{sev}</p>
                  <p className={`text-2xl font-bold ${severityColors[sev] || 'text-surface-400'}`}>{count}</p>
                  <p className="text-xs text-surface-400 mt-1">{pct}%</p>
                </Card>
              );
            })}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <Card title="Total CVEs" subtitle="Enriched intelligence">
              <div className="text-3xl font-bold">{stats.total_cves}</div>
            </Card>
            <Card title="Exploitable CVEs" subtitle="Exploit available">
              <div className="text-3xl font-bold text-success">{stats.exploit_count}</div>
            </Card>
            <Card title="Average CVSS" subtitle="Mean score">
              <div className="text-3xl font-bold">{stats.average_cvss}</div>
            </Card>
            <Card title="Average EPSS" subtitle="Exploit prediction">
              <div className="text-3xl font-bold">{stats.average_epss}</div>
            </Card>
            <Card title="KEV Findings" subtitle="Known exploited">
              <div className="text-3xl font-bold text-critical">{stats.kev_count}</div>
            </Card>
          </div>
        </>
      )}

      <Card title="CVE Intelligence" subtitle={`${total} records`}>
        <div className="flex flex-wrap gap-3 mb-6">
          <input
            type="text"
            placeholder="Search CVE ID or description..."
            className="input flex-1 min-w-[200px]"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="input w-auto"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            {severityOrder.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input
            type="text"
            placeholder="Vendor..."
            className="input w-40"
            value={vendorFilter}
            onChange={(e) => setVendorFilter(e.target.value)}
          />
          <label className="flex items-center gap-2 text-sm text-surface-600 dark:text-surface-400">
            <input type="checkbox" checked={kevOnly} onChange={(e) => setKevOnly(e.target.checked)} className="rounded" />
            KEV Only
          </label>
        </div>

        {error && (
          <div className="p-4 mb-4 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">
            {error}
            <Button variant="ghost" size="sm" className="ml-3" onClick={fetchData}>Retry</Button>
          </div>
        )}

        {loading ? (
          <LoadingSpinner size="md" text="Loading CVE intelligence..." />
        ) : cves.length === 0 ? (
          <div className="text-center py-12 text-surface-400">
            <p className="text-lg font-medium mb-1">No CVEs available</p>
            <p className="text-sm">Run the CVE intelligence stage to enrich vulnerability findings.</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-surface-200 dark:border-surface-700">
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('cve_id')}>
                      CVE ID{sortIndicator('cve_id')}
                    </th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase">Description</th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('cvss_score')}>
                      CVSS{sortIndicator('cvss_score')}
                    </th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('cvss_severity')}>
                      Severity{sortIndicator('cvss_severity')}
                    </th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('epss_score')}>
                      EPSS{sortIndicator('epss_score')}
                    </th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">KEV</th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('vendor')}>
                      Vendor{sortIndicator('vendor')}
                    </th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('published_date')}>
                      Published{sortIndicator('published_date')}
                    </th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">Priority</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                  {cves.map((c) => (
                    <tr key={c.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50 cursor-pointer" onClick={() => setSelectedCveId(c.id)}>
                      <td className="px-3 py-3 font-mono text-xs font-semibold text-primary-600 dark:text-primary-400">{c.cve_id}</td>
                      <td className="px-3 py-3 max-w-xs">
                        <p className="truncate text-surface-600 dark:text-surface-400">{c.description || '—'}</p>
                      </td>
                      <td className="px-3 py-3 text-center font-medium">{c.cvss_score ?? '—'}</td>
                      <td className="px-3 py-3 text-center">
                        <Badge variant={severityBadge(c.cvss_severity)}>{c.cvss_severity || '—'}</Badge>
                      </td>
                      <td className="px-3 py-3 text-center text-xs text-surface-500">
                        {c.epss_score != null ? `${(c.epss_score * 100).toFixed(1)}%` : '—'}
                      </td>
                      <td className="px-3 py-3 text-center">
                        {c.kev_status ? <Badge variant="danger">KEV</Badge> : '—'}
                      </td>
                      <td className="px-3 py-3 text-surface-600 dark:text-surface-400">{c.vendor || '—'}</td>
                      <td className="px-3 py-3 text-center text-xs text-surface-500">{c.published_date || '—'}</td>
                      <td className="px-3 py-3 text-center">
                        {c.remediation_priority ? (
                          <Badge variant={c.remediation_priority === 'Critical' ? 'danger' : c.remediation_priority === 'High' ? 'warning' : 'info'}>
                            {c.remediation_priority}
                          </Badge>
                        ) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between mt-4 pt-4 border-t border-surface-200 dark:border-surface-700">
              <span className="text-xs text-surface-500">Page {page} of {totalPages} ({total} CVEs)</span>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</Button>
                <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
              </div>
            </div>
          </>
        )}
      </Card>

      <CVEDetailModal
        cveId={selectedCveId}
        open={selectedCveId !== null}
        onClose={() => setSelectedCveId(null)}
      />
    </div>
  );
}
