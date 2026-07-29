import { useEffect, useState } from 'react';
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';

import { Card } from '../components/ui/Card';
import { StatCard } from '../components/ui/StatCard';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { Badge } from '../components/ui/Badge';
import { checkHealth } from '../services/healthService';
import { getHosts, getHostSummary } from '../services/hostService';
import type { HealthResponse } from '../types/health';
import type { Host } from '../types/host';
import { getStatusColor } from '../utils/helpers';

const riskData = [
  { name: 'Critical', value: 12, color: '#ef4444' },
  { name: 'High', value: 28, color: '#f97316' },
  { name: 'Medium', value: 45, color: '#eab308' },
  { name: 'Low', value: 67, color: '#22c55e' },
  { name: 'Info', value: 34, color: '#3b82f6' },
];

const recentScans = [
  { id: '1', name: 'Full Network Assessment', target: '192.168.56.0/24', status: 'completed', date: '2026-07-28T14:30:00' },
  { id: '2', name: 'Metasploitable2 Deep Scan', target: '192.168.56.20', status: 'completed', date: '2026-07-28T13:00:00' },
  { id: '3', name: 'Windows 7 Vuln Scan', target: '192.168.56.30', status: 'running', date: '2026-07-28T15:00:00' },
  { id: '4', name: 'Port Scan - All Hosts', target: '192.168.56.0/24', status: 'completed', date: '2026-07-27T16:00:00' },
];

export function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [summary, setSummary] = useState<{ total_hosts: number; alive_hosts: number } | null>(null);

  useEffect(() => {
    Promise.all([
      checkHealth(),
      getHosts(),
      getHostSummary(),
    ])
      .then(([healthRes, hostsRes, summaryRes]) => {
        setHealth(healthRes);
        setHosts(hostsRes.data);
        setSummary(summaryRes.data);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

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
          subtitle="192.168.56.0/24"
          trend={{ value: 0, positive: true }}
        />
        <StatCard
          title="Open Ports"
          value="43"
          subtitle="Across all targets"
          trend={{ value: 12, positive: false }}
        />
        <StatCard
          title="Vulnerabilities"
          value="93"
          subtitle="12 Critical · 28 High"
          trend={{ value: 8, positive: false }}
        />
        <StatCard
          title="Exploits Available"
          value="31"
          subtitle="Metasploit modules"
          trend={{ value: 5, positive: true }}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Risk Distribution" subtitle="Vulnerability severity breakdown">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {riskData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="Recent Scans" subtitle="Last 4 scan activities">
          <div className="space-y-3">
            {recentScans.map((scan) => (
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
                    {new Date(scan.date).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
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
