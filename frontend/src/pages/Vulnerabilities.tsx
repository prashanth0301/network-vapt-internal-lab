import { useCallback, useEffect, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import type { Vulnerability } from '../types/vulnerability';
import { getVulnerabilities, getVulnerabilitySummary } from '../services/vulnerabilityService';

function severityClass(severity: string | null): string {
  switch (severity) {
    case 'Critical': return 'text-critical';
    case 'High': return 'text-high';
    case 'Medium': return 'text-medium';
    case 'Low': return 'text-low';
    default: return 'text-info';
  }
}

function severityBadge(severity: string | null): 'danger' | 'warning' | 'info' | 'primary' | 'default' {
  switch (severity) {
    case 'Critical': return 'danger';
    case 'High': return 'warning';
    case 'Medium': return 'primary';
    case 'Low': return 'info';
    default: return 'default';
  }
}

export function Vulnerabilities() {
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [summary, setSummary] = useState<{ total_vulnerabilities: number; severity_counts: Record<string, number>; average_cvss: number; open_count: number } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sortBy, setSortBy] = useState('severity');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const perPage = 20;

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [vulnsRes, summaryRes] = await Promise.all([
        getVulnerabilities(
          severityFilter || undefined,
          undefined,
          undefined,
          search || undefined,
          sortBy,
          sortOrder,
          page,
          perPage,
        ),
        getVulnerabilitySummary(),
      ]);
      setVulns(vulnsRes.data);
      setTotal(vulnsRes.pagination.total);
      setTotalPages(vulnsRes.pagination.total_pages);
      setSummary(summaryRes.data);
    } catch {
      setError('Failed to load vulnerabilities. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [severityFilter, search, sortBy, sortOrder, page]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    setPage(1);
  }, [search, severityFilter, sortBy, sortOrder]);

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

  const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const severityColors: Record<string, string> = {
    Critical: 'text-critical', High: 'text-high', Medium: 'text-medium', Low: 'text-low', Info: 'text-info',
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {severityOrder.map((sev) => {
          const count = summary?.severity_counts?.[sev] ?? 0;
          const totalCount = summary?.total_vulnerabilities ?? 0;
          const pct = totalCount > 0 ? Math.round((count / totalCount) * 100) : 0;
          return (
            <Card key={sev} className="text-center">
              <p className="text-xs font-medium uppercase text-surface-400 mb-1">{sev}</p>
              <p className={`text-2xl font-bold ${severityColors[sev] || 'text-surface-400'}`}>{count}</p>
              <p className="text-xs text-surface-400 mt-1">{pct}%</p>
            </Card>
          );
        })}
      </div>

      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card title="Total Vulnerabilities" subtitle="All findings">
            <div className="text-3xl font-bold">{summary.total_vulnerabilities}</div>
          </Card>
          <Card title="Average CVSS" subtitle="Mean score">
            <div className="text-3xl font-bold">{summary.average_cvss}</div>
          </Card>
          <Card title="Open Findings" subtitle="Active vulnerabilities">
            <div className="text-3xl font-bold text-warning">{summary.open_count}</div>
          </Card>
        </div>
      )}

      <Card title="Vulnerability Inventory" subtitle={`${total} findings`}>
        <div className="flex flex-wrap gap-3 mb-6">
          <input
            type="text"
            placeholder="Search vulnerabilities..."
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
        </div>

        {error && (
          <div className="p-4 mb-4 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">
            {error}
            <Button variant="ghost" size="xs" className="ml-3" onClick={fetchData}>Retry</Button>
          </div>
        )}

        {loading ? (
          <LoadingSpinner size="md" text="Loading vulnerabilities..." />
        ) : vulns.length === 0 ? (
          <div className="text-center py-12 text-surface-400">
            <p className="text-lg font-medium mb-1">No vulnerabilities found</p>
            <p className="text-sm">Run a vulnerability scan to discover security issues.</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-surface-200 dark:border-surface-700">
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('name')}>
                      Vulnerability{sortIndicator('name')}
                    </th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase">Host</th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">Port</th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">CVE</th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('risk_score')}>
                      CVSS{sortIndicator('risk_score')}
                    </th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('severity')}>
                      Severity{sortIndicator('severity')}
                    </th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">Scanner</th>
                    <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                  {vulns.map((v) => (
                    <tr key={v.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                      <td className="px-3 py-3">
                        <span className="font-medium text-surface-900 dark:text-surface-100">{v.name}</span>
                        {v.description && (
                          <p className="text-xs text-surface-400 mt-0.5 line-clamp-1">{v.description}</p>
                        )}
                      </td>
                      <td className="px-3 py-3 font-mono text-xs text-surface-500">{v.host_ip || '—'}</td>
                      <td className="px-3 py-3 text-center text-surface-600 dark:text-surface-400">
                        {v.port_number ? `${v.port_number}/${v.port_protocol || 'tcp'}` : '—'}
                      </td>
                      <td className="px-3 py-3 text-center">
                        {v.cve_ids && v.cve_ids.length > 0 ? (
                          <span className="font-mono text-xs text-primary-500">{v.cve_ids[0]}</span>
                        ) : '—'}
                      </td>
                      <td className="px-3 py-3 text-center font-medium">{v.risk_score ?? '—'}</td>
                      <td className="px-3 py-3 text-center">
                        <Badge variant={severityBadge(v.severity)}>{v.severity || 'Info'}</Badge>
                      </td>
                      <td className="px-3 py-3 text-center text-xs text-surface-500">{v.scanner_name || '—'}</td>
                      <td className="px-3 py-3 text-center">
                        <Badge variant={v.status === 'open' ? 'warning' : 'success'}>{v.status || '—'}</Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between mt-4 pt-4 border-t border-surface-200 dark:border-surface-700">
              <span className="text-xs text-surface-500">Page {page} of {totalPages} ({total} vulnerabilities)</span>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>Previous</Button>
                <Button variant="ghost" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
