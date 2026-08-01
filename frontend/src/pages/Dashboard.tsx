import { useEffect, useState } from 'react';
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

import { Card } from '../components/ui/Card';
import { StatCard } from '../components/ui/StatCard';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { Badge } from '../components/ui/Badge';
import { checkHealth } from '../services/healthService';
import { getHosts, getHostSummary } from '../services/hostService';
import { getVulnerabilitySummary } from '../services/vulnerabilityService';
import { getCVEStatistics, getHighRiskCVEs } from '../services/cveService';
import { getExploitStatistics } from '../services/exploitService';
import { getPorts, getPortsByAssessment } from '../services/portService';
import { getAssessments, getAssessmentStatistics } from '../services/assessmentService';
import { getServices } from '../services/serviceIntelligenceService';
import { getActiveAssessmentId, useAssessmentChangeTick } from '../services/assessmentStore';
import type { Assessment, AssessmentStatistics } from '../types/assessment';
import type { CVE, CVEStatistics } from '../types/cve';
import type { ExploitStatistics } from '../types/exploit';
import type { HealthResponse } from '../types/health';
import type { Host } from '../types/host';
import type { Port } from '../types/port';
import type { VulnerabilitySummary } from '../types/vulnerability';

const COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  Info: '#3b82f6',
};

const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Info'];

async function fetchSafe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try { return await fn(); } catch { return fallback; }
}

export function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [ports, setPorts] = useState<Port[]>([]);
  const [summary, setSummary] = useState<{ total_hosts: number; alive_hosts: number } | null>(null);
  const [vulnSummary, setVulnSummary] = useState<VulnerabilitySummary | null>(null);
  const [cveStats, setCveStats] = useState<CVEStatistics | null>(null);
  const [highRiskCves, setHighRiskCves] = useState<CVE[]>([]);
  const [exploitStats, setExploitStats] = useState<ExploitStatistics | null>(null);
  const [recentScans, setRecentScans] = useState<Assessment[]>([]);
  const [servicesTotal, setServicesTotal] = useState(0);
  const [assessmentStats, setAssessmentStats] = useState<AssessmentStatistics | null>(null);
  const tick = useAssessmentChangeTick();

  useEffect(() => {
    const assessmentId = getActiveAssessmentId() ?? undefined;
    Promise.all([
      fetchSafe(checkHealth, null),
      fetchSafe(() => getHosts(assessmentId).then(r => r.data), []),
      fetchSafe(() => getHostSummary(assessmentId).then(r => r.data), null),
      fetchSafe(() => (assessmentId
        ? getPortsByAssessment(assessmentId).then(r => r.data)
        : getPorts().then(r => r.data)), []),
      fetchSafe(() => getVulnerabilitySummary(assessmentId).then(r => r.data), null),
      fetchSafe(() => getCVEStatistics(assessmentId).then(r => r.data), null),
      fetchSafe(() => getHighRiskCVEs(5, assessmentId).then(r => r.data), []),
      fetchSafe(() => getExploitStatistics(assessmentId).then(r => r.data), null),
      fetchSafe(() => getAssessments(undefined, undefined, 1, 4).then(r => r.data), []),
      fetchSafe(() => getServices(undefined, undefined, undefined, 'name', 'asc', 1, 1).then(r => r.pagination.total), 0),
      fetchSafe(() => getAssessmentStatistics().then(r => r.data), null),
    ]).then(([healthRes, hostsData, summaryData, portsData, vulnData, cveData, highRiskData, expData, scansData, servicesCount, assmtStats]) => {
      setHealth(healthRes);
      setHosts(hostsData);
      setSummary(summaryData);
      setPorts(portsData);
      setVulnSummary(vulnData);
      setCveStats(cveData);
      setHighRiskCves(highRiskData);
      setExploitStats(expData);
      setRecentScans(scansData);
      setServicesTotal(servicesCount);
      setAssessmentStats(assmtStats);
    }).finally(() => setLoading(false));
  }, [tick]);

  const riskData = severityOrder.map((sev) => ({
    name: sev,
    value: vulnSummary?.severity_counts?.[sev] ?? 0,
    color: COLORS[sev],
  }));

  const totalVulns = vulnSummary?.total_vulnerabilities ?? 0;
  const vulnSubtitle = vulnSummary
    ? severityOrder.filter((s) => (vulnSummary.severity_counts?.[s] ?? 0) > 0)
        .map((s) => `${vulnSummary.severity_counts[s]} ${s}`)
        .join(' · ')
    : 'No data';

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="md" text="Loading dashboard..." />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Live Hosts"
          value={String(summary?.alive_hosts ?? 0)}
          subtitle={`${summary?.total_hosts ?? 0} total hosts`}
        />
        <StatCard
          title="Open Ports"
          value={String(ports.filter((p) => p.state === 'open').length)}
          subtitle={`${ports.length} total port records`}
        />
        <StatCard
          title="Vulnerabilities"
          value={String(totalVulns)}
          subtitle={vulnSubtitle}
        />
        <StatCard
          title="Open Findings"
          value={String(vulnSummary?.open_count ?? 0)}
          subtitle={`Avg CVSS: ${vulnSummary?.average_cvss ?? '—'}`}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Services Detected"
          value={String(servicesTotal)}
          subtitle="Enriched service intelligence"
        />
        <StatCard
          title="Total Assessments"
          value={String(assessmentStats?.total ?? 0)}
          subtitle={`${assessmentStats?.active_count ?? 0} active`}
        />
        <StatCard
          title="Successful Scans"
          value={String(assessmentStats?.success_count ?? 0)}
          subtitle="Completed assessments"
        />
        <StatCard
          title="Failed Scans"
          value={String(assessmentStats?.failure_count ?? 0)}
          subtitle="Errored assessments"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total CVEs"
          value={String(cveStats?.total_cves ?? 0)}
          subtitle="Enriched intelligence"
        />
        <StatCard
          title="Average CVSS"
          value={String(cveStats?.average_cvss ?? '—')}
          subtitle="CVE base score"
        />
        <StatCard
          title="Average EPSS"
          value={String(cveStats?.average_epss ?? '—')}
          subtitle="Exploit probability"
        />
        <StatCard
          title="KEV Count"
          value={String(cveStats?.kev_count ?? 0)}
          subtitle="Known exploited vulnerabilities"
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Verified Exploits"
          value={String(exploitStats?.verified_count ?? 0)}
          subtitle={`${exploitStats?.success_rate ?? 0}% success rate`}
        />
        <StatCard
          title="Potential Exploits"
          value={String(exploitStats?.total_exploits ?? 0)}
          subtitle="Total exploit candidates"
        />
        <StatCard
          title="Sessions Created"
          value={String(exploitStats?.session_count ?? 0)}
          subtitle="Active sessions"
        />
        <StatCard
          title="Failed Attempts"
          value={String(exploitStats?.failed_count ?? 0)}
          subtitle="Verification failures"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card title="Risk Distribution" subtitle={`${totalVulns} total findings`}>
          <div className="h-72">
            {totalVulns > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskData.filter((d) => d.value > 0)}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {riskData.filter((d) => d.value > 0).map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-surface-400 text-sm">
                No vulnerability data yet
              </div>
            )}
          </div>
        </Card>

        <Card title="Recent Scans" subtitle="Last 4 assessments">
          <div className="space-y-3">
            {recentScans.length > 0 ? recentScans.map((scan) => (
              <div
                key={scan.id}
                className="flex items-center justify-between p-3 rounded-lg bg-surface-50 dark:bg-surface-800/50"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-surface-900 dark:text-surface-100 truncate">
                    {scan.name}
                  </p>
                  <p className="text-xs text-surface-400 mt-0.5">
                    {scan.target}
                  </p>
                </div>
                <div className="flex items-center gap-3 ml-4">
                  <Badge variant={scan.status === 'completed' ? 'success' : scan.status === 'running' ? 'warning' : 'default'}>
                    {scan.status}
                  </Badge>
                  <span className="text-xs text-surface-400 whitespace-nowrap">
                    {new Date(scan.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            )) : (
              <div className="text-sm text-surface-400 text-center py-4">No assessments yet — create one from the Workspace</div>
            )}
          </div>
        </Card>

        <Card title="Most Affected Vendors" subtitle="Top vendors by CVE count">
          <div className="space-y-2">
            {cveStats?.top_vendors && cveStats.top_vendors.length > 0 ? (
              cveStats.top_vendors.map((v) => (
                <div key={v.vendor} className="flex items-center justify-between p-2 rounded bg-surface-50 dark:bg-surface-800/50">
                  <span className="text-sm font-medium text-surface-700 dark:text-surface-300">{v.vendor}</span>
                  <Badge variant="warning">{v.count}</Badge>
                </div>
              ))
            ) : (
              <p className="text-sm text-surface-400 text-center py-4">No vendor data yet</p>
            )}
          </div>
        </Card>
      </div>

      <Card title="Host Summary" subtitle="Discovered hosts in the lab network">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-200 dark:border-surface-700">
                <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Host</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">IP</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">OS</th>
                <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Status</th>
                <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
              {hosts.map((host) => (
                <tr key={host.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                  <td className="px-4 py-3 font-medium text-surface-900 dark:text-surface-100">{host.hostname || 'Unknown'}</td>
                  <td className="px-4 py-3 text-surface-500 font-mono">{host.ip_address}</td>
                  <td className="px-4 py-3 text-surface-600 dark:text-surface-400">{host.os_name || '—'}</td>
                  <td className="px-4 py-3 text-center">
                    <Badge variant={host.is_alive ? 'success' : 'default'}>
                      {host.is_alive ? 'Alive' : 'Down'}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-center text-surface-600 dark:text-surface-400">
                    {host.latency ? `${host.latency.toFixed(1)}ms` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {highRiskCves.length > 0 && (
        <Card title="Highest Risk CVEs" subtitle="CVSS ≥ 7.0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-200 dark:border-surface-700">
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">CVE ID</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Description</th>
                  <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">CVSS</th>
                  <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Severity</th>
                  <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">EPSS</th>
                  <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">KEV</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Vendor</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                {highRiskCves.map((c) => (
                  <tr key={c.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                    <td className="px-4 py-3 font-mono text-xs font-semibold text-primary-600 dark:text-primary-400">{c.cve_id}</td>
                    <td className="px-4 py-3 max-w-xs truncate text-surface-600 dark:text-surface-400">{c.description || '—'}</td>
                    <td className="px-4 py-3 text-center font-medium">{c.cvss_score ?? '—'}</td>
                    <td className="px-4 py-3 text-center">
                      <Badge variant={c.cvss_severity === 'Critical' ? 'danger' : c.cvss_severity === 'High' ? 'warning' : 'info'}>
                        {c.cvss_severity || '—'}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-center text-xs">{c.epss_score != null ? `${(c.epss_score * 100).toFixed(1)}%` : '—'}</td>
                    <td className="px-4 py-3 text-center">{c.kev_status ? <Badge variant="danger">KEV</Badge> : '—'}</td>
                    <td className="px-4 py-3 text-surface-600 dark:text-surface-400">{c.vendor || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {loading ? (
        <Card>
          <LoadingSpinner size="sm" text="Connecting to backend..." />
        </Card>
      ) : health ? (
        <Card title="Backend Status" subtitle="API health check">
          <div className="flex items-center gap-6 text-sm">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-low" />
              <span className="text-surface-600 dark:text-surface-400">API:</span>
              <span className="font-medium">{health.services.api}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${health.database === 'connected' ? 'bg-low' : 'bg-critical'}`} />
              <span className="text-surface-600 dark:text-surface-400">Database:</span>
              <span className="font-medium">{health.database}</span>
            </div>
            <div className="text-surface-400">
              v{health.version} · {health.uptime_seconds}s uptime
            </div>
          </div>
        </Card>
      ) : (
        <Card title="Backend Status">
          <div className="flex items-center gap-2 text-sm text-critical">
            <span className="w-2 h-2 rounded-full bg-critical" />
            Backend unreachable — start the API server
          </div>
        </Card>
      )}
    </div>
  );
}
