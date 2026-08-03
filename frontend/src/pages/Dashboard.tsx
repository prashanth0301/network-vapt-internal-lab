import { useCallback, useContext, useEffect, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { AuthContext } from '../context/AuthContext';
import { getApiError } from '../services/api';
import { getDashboardSummary } from '../services/dashboardService';
import { useAssessmentChangeTick } from '../services/assessmentStore';
import type { DashboardSummary, PortSlice, ServiceSlice } from '../types/dashboard';

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  Info: '#3b82f6',
};

const RISK_LEVEL_COLOR: Record<string, 'danger' | 'warning' | 'success' | 'info' | 'default'> = {
  Critical: 'danger',
  High: 'warning',
  Medium: 'warning',
  Low: 'success',
  None: 'default',
};

function formatDuration(seconds: number | null): string {
  if (seconds === null) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function formatFileSize(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatRelative(iso: string | null): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const diffSec = Math.max(0, (Date.now() - then) / 1000);
  if (diffSec < 60) return 'just now';
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function statusVariant(status: string): 'success' | 'warning' | 'danger' | 'default' {
  if (status === 'completed') return 'success';
  if (status === 'running' || status === 'pending') return 'warning';
  if (status === 'failed' || status === 'error' || status === 'cancelled') return 'danger';
  return 'default';
}

export function Dashboard() {
  const { user } = useContext(AuthContext);
  const tick = useAssessmentChangeTick();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchSummary = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getDashboardSummary();
      setSummary(res.data);
      setLastUpdated(new Date());
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchSummary(); }, [fetchSummary, tick]);

  if (loading && !summary) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="md" text="Loading security dashboard..." />
      </div>
    );
  }

  const data = summary ?? emptySummary();

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100">
            Security Overview
          </h1>
          <p className="text-sm text-surface-400">
            {user ? `${user.username} · ` : ''}Last refreshed{' '}
            {lastUpdated ? lastUpdated.toLocaleTimeString() : 'never'}
          </p>
        </div>
        <Button size="sm" variant="secondary" onClick={fetchSummary} loading={loading}>
          Refresh
        </Button>
      </div>

      {error && !summary && (
        <div className="p-4 rounded-lg border border-critical/20 bg-critical/10 text-critical text-sm">
          Failed to load dashboard: {error}
          <button className="ml-3 underline" onClick={fetchSummary}>Retry</button>
        </div>
      )}

      <KpiRow data={data} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <SeverityPieCard data={data} />
        <VulnerabilityTrendCard data={data} />
        <TopOpenPortsCard data={data} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <ServiceDistributionCard data={data} />
        <RecentAssessmentsCard data={data} />
        <RecentReportsCard data={data} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <TopVulnerableHostsCard data={data} />
        <ScanDurationCard data={data} />
        <ActivityTimelineCard data={data} />
      </div>
    </div>
  );
}

function emptySummary(): DashboardSummary {
  return {
    severity_distribution: [],
    vulnerability_trend: [],
    top_open_ports: [],
    service_distribution: [],
    recent_assessments: [],
    recent_reports: [],
    top_vulnerable_hosts: [],
    risk_score: { score: 0, level: 'None', total: 0 },
    critical_count: 0,
    exploit_available_count: 0,
    scan_duration_stats: { count: 0, average_seconds: null, min_seconds: null, max_seconds: null },
    activity_timeline: [],
    totals: {
      vulnerabilities: 0, hosts: 0, open_ports: 0, services: 0, reports: 0, assessments: 0,
    },
  };
}

/* ------------------------------------------------------------------------- */
/* KPI row: Risk Score, Critical counter, Exploit counter, Total vulns       */
/* ------------------------------------------------------------------------- */

function KpiRow({ data }: { data: DashboardSummary }) {
  const risk = data.risk_score;
  const riskPct = Math.min(risk.score, 100);
  const ringColor =
    risk.score >= 70 ? '#ef4444' : risk.score >= 45 ? '#f97316' : risk.score >= 20 ? '#eab308' : '#22c55e';
  const circumference = 2 * Math.PI * 34;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
      <div className="card p-5 flex items-center gap-4">
        <div className="relative h-20 w-20 flex-shrink-0">
          <svg viewBox="0 0 80 80" className="h-full w-full -rotate-90">
            <circle cx="40" cy="40" r="34" fill="none" strokeWidth="8"
              className="stroke-surface-200 dark:stroke-surface-700" />
            <circle cx="40" cy="40" r="34" fill="none" strokeWidth="8"
              stroke={ringColor} strokeLinecap="round"
              strokeDasharray={`${(riskPct / 100) * circumference} ${circumference}`} />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-xl font-bold text-surface-900 dark:text-surface-100">{risk.score}</span>
          </div>
        </div>
        <div className="min-w-0">
          <p className="text-sm text-surface-500 dark:text-surface-400">Risk Score</p>
          <div className="mt-1"><Badge variant={RISK_LEVEL_COLOR[risk.level] ?? 'default'}>{risk.level}</Badge></div>
          <p className="text-xs text-surface-400 mt-1">{risk.total} findings assessed</p>
        </div>
      </div>

      <div className="card p-5 flex items-center gap-4">
        <div className="p-3 rounded-lg bg-critical/10 text-critical flex-shrink-0">
          <span className="text-2xl">🔥</span>
        </div>
        <div className="min-w-0">
          <p className="text-sm text-surface-500 dark:text-surface-400">Critical Vulnerabilities</p>
          <p className="text-2xl font-bold text-surface-900 dark:text-surface-100">{data.critical_count}</p>
          <p className="text-xs text-surface-400 mt-1">Require immediate attention</p>
        </div>
      </div>

      <div className="card p-5 flex items-center gap-4">
        <div className="p-3 rounded-lg bg-medium/10 text-medium flex-shrink-0">
          <span className="text-2xl">💣</span>
        </div>
        <div className="min-w-0">
          <p className="text-sm text-surface-500 dark:text-surface-400">Exploits Available</p>
          <p className="text-2xl font-bold text-surface-900 dark:text-surface-100">{data.exploit_available_count}</p>
          <p className="text-xs text-surface-400 mt-1">Public exploits verified</p>
        </div>
      </div>

      <div className="card p-5 flex items-center gap-4">
        <div className="p-3 rounded-lg bg-info/10 text-info flex-shrink-0">
          <span className="text-2xl">🛡️</span>
        </div>
        <div className="min-w-0">
          <p className="text-sm text-surface-500 dark:text-surface-400">Total Vulnerabilities</p>
          <p className="text-2xl font-bold text-surface-900 dark:text-surface-100">{data.totals.vulnerabilities}</p>
          <p className="text-xs text-surface-400 mt-1">
            {data.totals.hosts} hosts · {data.totals.open_ports} open ports
          </p>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------------- */
/* 1. Severity Pie Chart                                                     */
/* ------------------------------------------------------------------------- */

function SeverityPieCard({ data }: { data: DashboardSummary }) {
  const slices = data.severity_distribution.filter((s) => s.count > 0);
  const total = data.totals.vulnerabilities;

  return (
    <Card title="Severity Distribution" subtitle="Findings by severity">
      <div className="h-72 relative">
        {slices.length > 0 ? (
          <>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={slices}
                  dataKey="count"
                  nameKey="severity"
                  cx="50%"
                  cy="50%"
                  innerRadius={62}
                  outerRadius={95}
                  paddingAngle={2}
                >
                  {slices.map((s) => (
                    <Cell key={s.severity} fill={SEVERITY_COLORS[s.severity] ?? '#64748b'} />
                  ))}
                </Pie>
                <Tooltip formatter={(value: number, name: string) => [`${value} findings`, name]} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-3xl font-bold text-surface-900 dark:text-surface-100">{total}</span>
              <span className="text-xs text-surface-400">findings</span>
            </div>
          </>
        ) : (
          <div className="flex items-center justify-center h-full text-surface-400 text-sm">
            No vulnerability data yet
          </div>
        )}
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------------- */
/* 2. Vulnerability Trend                                                    */
/* ------------------------------------------------------------------------- */

function VulnerabilityTrendCard({ data }: { data: DashboardSummary }) {
  const points = data.vulnerability_trend.map((p) => ({
    date: p.date.slice(5),
    full: p.date,
    count: p.count,
  }));

  return (
    <Card title="Vulnerability Trend" subtitle="Last 14 days">
      <div className="h-72">
        {points.some((p) => p.count > 0) ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={points} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="vulnTrend" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#64748b22" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis allowDecimals={false} tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
              <Tooltip
                labelFormatter={(label) => {
                  const p = points.find((x) => x.date === label);
                  return p?.full ?? label;
                }}
              />
              <Area type="monotone" dataKey="count" name="Findings" stroke="#ef4444"
                strokeWidth={2} fill="url(#vulnTrend)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-full text-surface-400 text-sm">
            No findings recorded in the last 14 days
          </div>
        )}
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------------- */
/* 3. Top Open Ports                                                         */
/* ------------------------------------------------------------------------- */

function TopOpenPortsCard({ data }: { data: DashboardSummary }) {
  const ports: PortSlice[] = data.top_open_ports;

  return (
    <Card title="Top Open Ports" subtitle="Most common open ports across hosts">
      <div className="h-72">
        {ports.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={ports} layout="vertical" margin={{ top: 4, right: 24, left: 8, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#64748b22" horizontal={false} />
              <XAxis type="number" allowDecimals={false} tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis
                type="category"
                dataKey="port"
                width={54}
                tick={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}
                tickLine={false}
                axisLine={false}
                tickFormatter={(port: number) => String(port)}
              />
              <Tooltip
                cursor={{ fill: '#64748b11' }}
                formatter={(value: number) => [`${value} hosts`, 'Open']}
                labelFormatter={(port) => {
                  const p = ports.find((x) => x.port === Number(port));
                  return p?.label ? `Port ${port} (${p.label})` : `Port ${port}`;
                }}
              />
              <Bar dataKey="count" name="Hosts" radius={[0, 4, 4, 0]} fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-full text-surface-400 text-sm">
            No open ports detected
          </div>
        )}
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------------- */
/* 4. Service Distribution                                                   */
/* ------------------------------------------------------------------------- */

function ServiceDistributionCard({ data }: { data: DashboardSummary }) {
  const services: ServiceSlice[] = data.service_distribution;
  const max = Math.max(1, ...services.map((s) => s.count));

  return (
    <Card title="Service Distribution" subtitle="Top services by exposure">
      {services.length > 0 ? (
        <div className="space-y-3 mt-1">
          {services.map((s) => (
            <div key={s.name}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm text-surface-700 dark:text-surface-300 truncate mr-2">{s.name}</span>
                <span className="text-xs font-mono text-surface-500">{s.count}</span>
              </div>
              <div className="w-full bg-surface-200 dark:bg-surface-700 rounded-full overflow-hidden h-2">
                <div
                  className="h-full bg-primary-500 rounded-full transition-all duration-500"
                  style={{ width: `${(s.count / max) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex items-center justify-center h-48 text-surface-400 text-sm">
          No services detected
        </div>
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------------- */
/* 5. Recent Assessments                                                     */
/* ------------------------------------------------------------------------- */

function RecentAssessmentsCard({ data }: { data: DashboardSummary }) {
  const items = data.recent_assessments;

  return (
    <Card title="Recent Assessments" subtitle={`${data.totals.assessments} total`}>
      <div className="space-y-3">
        {items.length > 0 ? items.map((a) => (
          <div key={a.id} className="flex items-center justify-between p-3 rounded-lg bg-surface-50 dark:bg-surface-800/50">
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-surface-900 dark:text-surface-100 truncate">{a.name}</p>
              <p className="text-xs text-surface-400 mt-0.5 truncate">{a.target}</p>
            </div>
            <div className="flex items-center gap-3 ml-4 flex-shrink-0">
              <Badge variant={statusVariant(a.status)}>{a.status}</Badge>
              <span className="text-xs text-surface-400 whitespace-nowrap">{formatRelative(a.created_at)}</span>
            </div>
          </div>
        )) : (
          <div className="text-sm text-surface-400 text-center py-4">
            No assessments yet — create one from the Workspace
          </div>
        )}
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------------- */
/* 6. Recent Reports                                                         */
/* ------------------------------------------------------------------------- */

function RecentReportsCard({ data }: { data: DashboardSummary }) {
  const items = data.recent_reports;

  return (
    <Card title="Recent Reports" subtitle={`${data.totals.reports} generated`}>
      <div className="space-y-3">
        {items.length > 0 ? items.map((r) => (
          <div key={r.id} className="flex items-center justify-between p-3 rounded-lg bg-surface-50 dark:bg-surface-800/50">
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium text-surface-900 dark:text-surface-100 truncate">{r.title}</p>
              <p className="text-xs text-surface-400 mt-0.5">{formatRelative(r.created_at)}</p>
            </div>
            <div className="flex items-center gap-2 ml-4 flex-shrink-0">
              <Badge variant="info">{r.report_type}</Badge>
              <span className="text-xs font-mono text-surface-500 uppercase">{r.format}</span>
              <span className="text-xs text-surface-400">{formatFileSize(r.file_size)}</span>
            </div>
          </div>
        )) : (
          <div className="text-sm text-surface-400 text-center py-4">
            No reports generated yet
          </div>
        )}
      </div>
    </Card>
  );
}

/* ------------------------------------------------------------------------- */
/* 7. Top Vulnerable Hosts                                                   */
/* ------------------------------------------------------------------------- */

function TopVulnerableHostsCard({ data }: { data: DashboardSummary }) {
  const hosts = data.top_vulnerable_hosts;
  const max = Math.max(1, ...hosts.map((h) => h.count));

  return (
    <Card title="Top Vulnerable Hosts" subtitle="Hosts with most findings">
      {hosts.length > 0 ? (
        <div className="space-y-3 mt-1">
          {hosts.map((h) => (
            <div key={h.ip_address}>
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="font-mono text-sm text-surface-900 dark:text-surface-100">{h.ip_address}</span>
                  {h.hostname && (
                    <span className="text-xs text-surface-400 truncate">{h.hostname}</span>
                  )}
                </div>
                <Badge variant={h.count >= 10 ? 'danger' : h.count >= 5 ? 'warning' : 'default'}>
                  {h.count}
                </Badge>
              </div>
              <div className="w-full bg-surface-200 dark:bg-surface-700 rounded-full overflow-hidden h-2">
                <div
                  className="h-full bg-critical rounded-full transition-all duration-500"
                  style={{ width: `${(h.count / max) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="flex items-center justify-center h-48 text-surface-400 text-sm">
          No hosts with vulnerabilities
        </div>
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------------- */
/* 11. Scan Duration Statistics                                              */
/* ------------------------------------------------------------------------- */

function ScanDurationCard({ data }: { data: DashboardSummary }) {
  const stats = data.scan_duration_stats;

  const rows = [
    { label: 'Average', value: stats.average_seconds },
    { label: 'Fastest', value: stats.min_seconds },
    { label: 'Slowest', value: stats.max_seconds },
  ];

  return (
    <Card title="Scan Duration Statistics" subtitle={`${stats.count} completed scans measured`}>
      {stats.count > 0 ? (
        <div className="space-y-4">
          {rows.map((row) => (
            <div key={row.label} className="flex items-center justify-between p-3 rounded-lg bg-surface-50 dark:bg-surface-800/50">
              <span className="text-sm text-surface-600 dark:text-surface-400">{row.label}</span>
              <span className="font-mono text-sm font-semibold text-surface-900 dark:text-surface-100">
                {formatDuration(row.value)}
              </span>
            </div>
          ))}
          <p className="text-xs text-surface-400">
            Median-scope full assessments complete in around{' '}
            {formatDuration(stats.average_seconds)} on average.
          </p>
        </div>
      ) : (
        <div className="flex items-center justify-center h-48 text-surface-400 text-sm">
          No completed scans yet
        </div>
      )}
    </Card>
  );
}

/* ------------------------------------------------------------------------- */
/* 12. Latest Activity Timeline                                              */
/* ------------------------------------------------------------------------- */

function ActivityTimelineCard({ data }: { data: DashboardSummary }) {
  const items = data.activity_timeline;

  const iconFor = (action: string) => {
    if (action.includes('login')) return '🔑';
    if (action.includes('assessment') || action.includes('scan')) return '📡';
    if (action.includes('report')) return '📄';
    if (action.includes('settings')) return '⚙️';
    if (action.includes('user')) return '👤';
    if (action.includes('exploit')) return '💣';
    return '•';
  };

  return (
    <Card title="Latest Activity" subtitle="Recent platform events">
      {items.length > 0 ? (
        <div className="relative">
          <div className="absolute left-[7px] top-1 bottom-1 w-px bg-surface-200 dark:bg-surface-700" />
          <div className="space-y-4">
            {items.map((item, idx) => (
              <div key={idx} className="flex items-start gap-3 pl-0">
                <div className="relative z-10 flex h-4 w-4 items-center justify-center rounded-full bg-surface-100 dark:bg-surface-700 border border-surface-200 dark:border-surface-600 text-[9px] flex-shrink-0 mt-0.5">
                  {iconFor(item.action)}
                </div>
                <div className="min-w-0">
                  <p className="text-sm text-surface-800 dark:text-surface-200 font-medium break-words">
                    {item.action.replace(/_/g, ' ')}
                  </p>
                  <p className="text-xs text-surface-400 mt-0.5">
                    {item.user} · {formatRelative(item.timestamp)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="flex items-center justify-center h-48 text-surface-400 text-sm">
          No recent activity
        </div>
      )}
    </Card>
  );
}
