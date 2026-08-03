import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { classNames, formatDate } from '../utils/helpers';
import { getApiError } from '../services/api';
import { getHostDetails } from '../services/hostService';
import { downloadReport } from '../services/reportService';
import type {
  BannerInfo,
  CveInfo,
  EvidenceInfo,
  ExploitInfo,
  HostDetails,
  PortInfo,
  ReportInfo,
  ScanHistoryInfo,
  ServiceInfo,
  VulnerabilityInfo,
} from '../types/host';

type TabId =
  | 'overview'
  | 'os'
  | 'ports'
  | 'services'
  | 'banners'
  | 'vulnerabilities'
  | 'cves'
  | 'exploits'
  | 'evidence'
  | 'scan_history'
  | 'reports';

const TABS: { id: TabId; label: string; countKey?: keyof HostDetails['summary'] }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'os', label: 'OS Information' },
  { id: 'ports', label: 'Open Ports', countKey: 'ports' },
  { id: 'services', label: 'Services', countKey: 'services' },
  { id: 'banners', label: 'Banners', countKey: 'banners' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', countKey: 'vulnerabilities' },
  { id: 'cves', label: 'CVEs', countKey: 'cves' },
  { id: 'exploits', label: 'Exploits', countKey: 'exploits' },
  { id: 'evidence', label: 'Evidence', countKey: 'evidence' },
  { id: 'scan_history', label: 'Scan History', countKey: 'scans' },
  { id: 'reports', label: 'Generated Reports', countKey: 'reports' },
];

const SEVERITY_HEX: Record<string, string> = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#0ea5e9',
};

const STATUS_VARIANT: Record<string, 'success' | 'danger' | 'warning' | 'default'> = {
  completed: 'success',
  open: 'danger',
  available: 'success',
  running: 'warning',
  failed: 'danger',
  up: 'success',
  down: 'default',
};

function sortValue(a: unknown, b: unknown): number {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b));
}

interface DataTableColumn<T> {
  key: string;
  header: string;
  render?: (item: T) => ReactNode;
  align?: 'left' | 'right';
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  data: T[];
  keyExtractor: (item: T) => string;
  emptyMessage?: string;
}

function DataTable<T>({ columns, data, keyExtractor, emptyMessage }: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');

  const rows = useMemo(() => {
    if (!sortKey) return data;
    return [...data].sort((a, b) => {
      const av = (a as Record<string, unknown>)[sortKey];
      const bv = (b as Record<string, unknown>)[sortKey];
      return sortValue(av, bv) * (sortDir === 'asc' ? 1 : -1);
    });
  }, [data, sortKey, sortDir]);

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  if (data.length === 0) {
    return (
      <div className="py-10 text-center">
        <p className="text-surface-400 text-sm">{emptyMessage ?? 'No data available'}</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-surface-200 dark:border-surface-700">
            {columns.map((col) => (
              <th
                key={col.key}
                className={classNames(
                  'px-4 py-3 text-xs font-medium text-surface-500 dark:text-surface-400 uppercase tracking-wider',
                  col.align === 'right' && 'text-right',
                )}
              >
                <button
                  className={classNames(
                    'inline-flex items-center gap-1 hover:text-surface-700 dark:hover:text-surface-200',
                    sortKey === col.key && 'text-primary-600 dark:text-primary-400',
                  )}
                  onClick={() => handleSort(col.key)}
                >
                  {col.header}
                  {sortKey === col.key && (sortDir === 'asc' ? '\u2191' : '\u2193')}
                </button>
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
          {rows.map((item) => (
            <tr key={keyExtractor(item)} className="hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors">
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={classNames(
                    'px-4 py-3 text-surface-700 dark:text-surface-300',
                    col.align === 'right' && 'text-right',
                  )}
                >
                  {col.render ? col.render(item) : ((item as Record<string, unknown>)[col.key] as ReactNode)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return <span className="text-surface-400">{'\u2014'}</span>;
  const color = SEVERITY_HEX[severity.toLowerCase()] || SEVERITY_HEX.info;
  return (
    <span
      className="inline-flex items-center font-medium rounded-full px-2 py-0.5 text-xs uppercase"
      style={{ backgroundColor: `${color}1a`, color }}
    >
      {severity}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const variant = STATUS_VARIANT[status.toLowerCase()] ?? 'default';
  return <Badge variant={variant}>{status}</Badge>;
}

function Field({ label, value, mono = false }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div className="p-3 rounded-lg bg-surface-50 dark:bg-surface-800/50">
      <div className="text-xs font-medium text-surface-500 dark:text-surface-400 mb-1">{label}</div>
      <div className={classNames('text-sm text-surface-800 dark:text-surface-200', mono && 'font-mono text-xs')}>
        {value ?? '\u2014'}
      </div>
    </div>
  );
}

function formatSeconds(seconds: number | null): string {
  if (seconds == null) return '\u2014';
  if (seconds >= 3600) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${h}h ${m}m`;
  }
  if (seconds >= 60) {
    const m = Math.floor(seconds / 60);
    return `${m}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
}

function formatFileSize(bytes: number | null): string {
  if (bytes == null) return '\u2014';
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function HostDetailsPage() {
  const { hostId } = useParams<{ hostId: string }>();
  const navigate = useNavigate();
  const [details, setDetails] = useState<HostDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [filters, setFilters] = useState<Partial<Record<TabId, string>>>({});
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!hostId) return;
    setLoading(true);
    setError(null);
    getHostDetails(hostId)
      .then((res) => setDetails(res.data))
      .catch((e) => setError(getApiError(e)))
      .finally(() => setLoading(false));
  }, [hostId]);

  useEffect(() => {
    load();
  }, [load]);

  const filterText = (tab: TabId) => (filters[tab] ?? '').toLowerCase();

  const filtered = useMemo(() => {
    if (!details) return null;
    const match = (tab: TabId, text: string) => {
      const q = filterText(tab);
      return !q || text.toLowerCase().includes(q);
    };
    return {
      ports: details.open_ports.filter((p) => match('ports', `${p.port} ${p.protocol} ${p.state} ${p.reason ?? ''}`)),
      services: details.services.filter((s) =>
        match('services', `${s.port} ${s.name ?? ''} ${s.product ?? ''} ${s.version ?? ''} ${s.category ?? ''}`),
      ),
      banners: details.banners.filter((b) =>
        match('banners', `${b.port} ${b.service_name ?? ''} ${b.product ?? ''} ${b.banner}`),
      ),
      vulnerabilities: details.vulnerabilities.filter((v) =>
        match('vulnerabilities', `${v.name} ${v.severity ?? ''} ${v.status ?? ''} ${(v.cve_ids ?? []).join(' ')}`),
      ),
      cves: details.cves.filter((c) =>
        match('cves', `${c.cve_id} ${c.cvss_severity ?? ''} ${c.description ?? ''} ${c.metasploit_module ?? ''}`),
      ),
      exploits: details.exploits.filter((e) =>
        match('exploits', `${e.module_name ?? ''} ${e.exploit_name ?? ''} ${e.cve ?? ''} ${e.status ?? ''} ${e.provider}`),
      ),
      evidence: details.evidence.filter((ev) =>
        match('evidence', `${ev.name} ${ev.severity ?? ''} ${ev.evidence ?? ''} ${ev.plugin_output ?? ''}`),
      ),
      scan_history: details.scan_history.filter((s) =>
        match('scan_history', `${s.name} ${s.scan_type} ${s.target} ${s.status}`),
      ),
      reports: details.reports.filter((r) =>
        match('reports', `${r.title} ${r.report_type} ${r.format}`),
      ),
    };
  }, [details, filters]);

  const handleDownload = async (report: ReportInfo) => {
    setDownloadingId(report.id);
    setDownloadError(null);
    try {
      const blob = await downloadReport(report.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.title}.${report.format.toLowerCase()}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setDownloadError(getApiError(e));
    } finally {
      setDownloadingId(null);
    }
  };

  if (loading) {
    return (
      <Card title="Host Details" subtitle="Loading...">
        <LoadingSpinner text="Loading host details..." />
      </Card>
    );
  }

  if (error || !details || !filtered) {
    return (
      <Card title="Host Details">
        <div className="p-3 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm">
          {error || 'Host not found'}
        </div>
        <div className="mt-4">
          <Button variant="ghost" size="sm" onClick={() => navigate('/hosts')}>
            \u2190 Back to Hosts
          </Button>
        </div>
      </Card>
    );
  }

  const { host, os_information: os, summary } = details;

  const overviewStats: { label: string; value: number }[] = [
    { label: 'Ports', value: summary.ports },
    { label: 'Open Ports', value: summary.open_ports },
    { label: 'Services', value: summary.services },
    { label: 'Banners', value: summary.banners },
    { label: 'Vulnerabilities', value: summary.vulnerabilities },
    { label: 'CVEs', value: summary.cves },
    { label: 'Exploits', value: summary.exploits },
    { label: 'Evidence', value: summary.evidence },
    { label: 'Scans', value: summary.scans },
    { label: 'Reports', value: summary.reports },
  ];

  const portColumns: DataTableColumn<PortInfo>[] = [
    { key: 'port', header: 'Port', render: (p) => <span className="font-mono">{p.port}</span> },
    { key: 'protocol', header: 'Protocol', render: (p) => <span className="font-mono uppercase text-xs">{p.protocol}</span> },
    { key: 'state', header: 'State', render: (p) => <StatusBadge status={p.state} /> },
    { key: 'reason', header: 'Reason', render: (p) => <span className="font-mono text-xs text-surface-400">{p.reason ?? '\u2014'}</span> },
    { key: 'created_at', header: 'Discovered', align: 'right', render: (p) => <span className="text-xs text-surface-400">{formatDate(p.created_at)}</span> },
  ];

  const serviceColumns: DataTableColumn<ServiceInfo>[] = [
    { key: 'port', header: 'Port', render: (s) => <span className="font-mono">{s.port}/{s.protocol}</span> },
    { key: 'name', header: 'Service', render: (s) => s.name ?? '\u2014' },
    { key: 'product', header: 'Product', render: (s) => s.product ?? '\u2014' },
    { key: 'version', header: 'Version', render: (s) => s.version ?? '\u2014' },
    { key: 'category', header: 'Category', render: (s) => (s.category ? <Badge>{s.category}</Badge> : '\u2014') },
    { key: 'confidence', header: 'Confidence', align: 'right', render: (s) => (s.confidence != null ? `${s.confidence}%` : '\u2014') },
  ];

  const bannerColumns: DataTableColumn<BannerInfo>[] = [
    { key: 'port', header: 'Port', render: (b) => <span className="font-mono">{b.port}/{b.protocol}</span> },
    { key: 'service_name', header: 'Service', render: (b) => b.service_name ?? '\u2014' },
    { key: 'product', header: 'Product', render: (b) => b.product ?? '\u2014' },
    { key: 'version', header: 'Version', render: (b) => b.version ?? '\u2014' },
    {
      key: 'banner',
      header: 'Banner',
      render: (b) => (
        <span className="font-mono text-xs text-surface-600 dark:text-surface-300" title={b.banner}>
          {b.banner.length > 90 ? `${b.banner.slice(0, 90)}\u2026` : b.banner}
        </span>
      ),
    },
  ];

  const vulnColumns: DataTableColumn<VulnerabilityInfo>[] = [
    { key: 'name', header: 'Finding', render: (v) => <span className="font-medium">{v.name}</span> },
    { key: 'severity', header: 'Severity', render: (v) => <SeverityBadge severity={v.severity} /> },
    { key: 'risk_score', header: 'Risk Score', align: 'right', render: (v) => (v.risk_score != null ? v.risk_score.toFixed(1) : '\u2014') },
    { key: 'status', header: 'Status', render: (v) => <StatusBadge status={v.status ?? 'unknown'} /> },
    { key: 'cve_count', header: 'CVEs', align: 'right', render: (v) => (v.cve_ids?.length ? (v.cve_ids.length) : v.cve_count ?? 0) },
  ];

  const cveColumns: DataTableColumn<CveInfo>[] = [
    { key: 'cve_id', header: 'CVE', render: (c) => <span className="font-mono font-medium">{c.cve_id}</span> },
    { key: 'cvss_score', header: 'CVSS', align: 'right', render: (c) => (c.cvss_score != null ? c.cvss_score.toFixed(1) : '\u2014') },
    { key: 'cvss_severity', header: 'Severity', render: (c) => <SeverityBadge severity={c.cvss_severity} /> },
    { key: 'epss_score', header: 'EPSS', align: 'right', render: (c) => (c.epss_score != null ? c.epss_score.toFixed(3) : '\u2014') },
    {
      key: 'description',
      header: 'Description',
      render: (c) => (
        <span className="text-xs text-surface-600 dark:text-surface-400" title={c.description ?? ''}>
          {c.description ? (c.description.length > 100 ? `${c.description.slice(0, 100)}\u2026` : c.description) : '\u2014'}
        </span>
      ),
    },
    {
      key: 'exploit_available',
      header: 'Exploit',
      render: (c) =>
        c.exploit_available ? (
          <Badge variant="danger">Yes</Badge>
        ) : (
          <span className="text-surface-400">No</span>
        ),
    },
    { key: 'kev_status', header: 'KEV', render: (c) => (c.kev_status ? <Badge variant="warning">Listed</Badge> : <span className="text-surface-400">No</span>) },
  ];

  const exploitColumns: DataTableColumn<ExploitInfo>[] = [
    { key: 'module_name', header: 'Module', render: (e) => <span className="font-mono text-xs">{e.module_name ?? e.exploit_name ?? '\u2014'}</span> },
    { key: 'cve', header: 'CVE', render: (e) => (e.cve ? <span className="font-mono text-xs">{e.cve}</span> : '\u2014') },
    { key: 'provider', header: 'Provider', render: (e) => <Badge>{e.provider}</Badge> },
    { key: 'rank', header: 'Rank', render: (e) => e.rank ?? '\u2014' },
    { key: 'status', header: 'Status', render: (e) => <StatusBadge status={e.status ?? 'unknown'} /> },
    { key: 'verified', header: 'Verified', render: (e) => (e.verified ? <Badge variant="success">Yes</Badge> : <span className="text-surface-400">No</span>) },
    { key: 'duration', header: 'Duration', align: 'right', render: (e) => (e.duration != null ? `${e.duration.toFixed(1)}s` : '\u2014') },
  ];

  const evidenceColumns: DataTableColumn<EvidenceInfo>[] = [
    { key: 'name', header: 'Finding', render: (ev) => <span className="font-medium">{ev.name}</span> },
    { key: 'severity', header: 'Severity', render: (ev) => <SeverityBadge severity={ev.severity} /> },
    {
      key: 'evidence',
      header: 'Evidence',
      render: (ev) => (
        <span className="font-mono text-xs text-surface-600 dark:text-surface-300" title={ev.evidence ?? ''}>
          {ev.evidence ? (ev.evidence.length > 90 ? `${ev.evidence.slice(0, 90)}\u2026` : ev.evidence) : ev.plugin_output ? 'plugin output' : '\u2014'}
        </span>
      ),
    },
    { key: 'cve_ids', header: 'CVEs', render: (ev) => (ev.cve_ids?.length ? ev.cve_ids.join(', ') : '\u2014') },
  ];

  const scanColumns: DataTableColumn<ScanHistoryInfo>[] = [
    { key: 'name', header: 'Scan', render: (s) => <span className="font-medium">{s.name}</span> },
    { key: 'scan_type', header: 'Type', render: (s) => <Badge>{s.scan_type}</Badge> },
    { key: 'target', header: 'Target', render: (s) => <span className="font-mono text-xs">{s.target}</span> },
    { key: 'status', header: 'Status', render: (s) => <StatusBadge status={s.status} /> },
    { key: 'duration_seconds', header: 'Duration', align: 'right', render: (s) => formatSeconds(s.duration_seconds) },
    { key: 'started_at', header: 'Started', render: (s) => (s.started_at ? <span className="text-xs text-surface-400">{formatDate(s.started_at)}</span> : '\u2014') },
  ];

  const reportColumns: DataTableColumn<ReportInfo>[] = [
    { key: 'title', header: 'Report', render: (r) => <span className="font-medium">{r.title}</span> },
    { key: 'report_type', header: 'Type', render: (r) => <Badge>{r.report_type}</Badge> },
    { key: 'format', header: 'Format', render: (r) => <span className="font-mono text-xs uppercase">{r.format}</span> },
    { key: 'file_size', header: 'Size', align: 'right', render: (r) => formatFileSize(r.file_size) },
    { key: 'created_at', header: 'Generated', render: (r) => <span className="text-xs text-surface-400">{formatDate(r.created_at)}</span> },
    {
      key: 'actions',
      header: '',
      align: 'right',
      render: (r) => (
        <Button variant="primary" size="sm" loading={downloadingId === r.id} onClick={() => handleDownload(r)}>
          Download
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <Card
        title={`Host ${host.ip_address}`}
        subtitle={host.hostname ?? 'No hostname resolved'}
        action={
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={() => navigate('/hosts')}>
              {'\u2190'} Back to Hosts
            </Button>
          </div>
        }
      >
        <div className="flex items-center gap-4 mb-4">
          <StatusBadge status={os.is_alive ? 'up' : 'down'} />
          {os.os_name && <span className="text-sm text-surface-600 dark:text-surface-300">{os.os_name} {os.os_version ?? ''}{os.os_accuracy != null ? ` (${os.os_accuracy}%)` : ''}</span>}
          {os.mac_address && <span className="font-mono text-xs text-surface-400">{os.mac_address}</span>}
        </div>

        {downloadError && (
          <div className="mb-4 p-3 rounded-lg bg-critical/10 border border-critical/30 text-critical text-sm">
            {downloadError}
          </div>
        )}

        <div className="flex flex-wrap border-b border-surface-200 dark:border-surface-700 gap-1">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
                activeTab === tab.id
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-surface-500 hover:text-surface-700 dark:hover:text-surface-300'
              }`}
            >
              {tab.label}
              {tab.countKey != null && summary[tab.countKey] > 0 && (
                <span className="ml-1.5 text-xs font-mono text-surface-400">{summary[tab.countKey]}</span>
              )}
            </button>
          ))}
        </div>

        {activeTab === 'overview' && (
          <div className="pt-4 grid grid-cols-2 md:grid-cols-5 gap-3">
            {overviewStats.map((stat) => (
              <div key={stat.label} className="p-4 rounded-lg bg-surface-50 dark:bg-surface-800/50">
                <div className="text-2xl font-semibold text-surface-900 dark:text-surface-100">{stat.value}</div>
                <div className="text-xs text-surface-500 dark:text-surface-400 mt-1">{stat.label}</div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'os' && (
          <div className="pt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
            <Field label="Hostname" value={os.hostname} mono />
            <Field label="OS Name" value={os.os_name} />
            <Field label="OS Version" value={os.os_version} />
            <Field label="OS Accuracy" value={os.os_accuracy != null ? `${os.os_accuracy}%` : null} />
            <Field label="Vendor" value={os.vendor} />
            <Field label="MAC Address" value={os.mac_address} mono />
            <Field label="Status" value={os.is_alive ? 'up' : 'down'} />
            <Field label="Latency" value={os.latency != null ? `${os.latency.toFixed(1)}ms` : null} />
            <Field label="First Seen" value={os.first_seen ? formatDate(os.first_seen) : null} />
            <Field label="Last Seen" value={os.last_seen ? formatDate(os.last_seen) : null} />
          </div>
        )}

        {activeTab === 'ports' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter by port / protocol / state..."
                value={filters.ports ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, ports: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.ports.length} / {details.open_ports.length}</span>
            </div>
            <DataTable columns={portColumns} data={filtered.ports} keyExtractor={(p) => p.id} emptyMessage="No ports discovered for this host." />
          </div>
        )}

        {activeTab === 'services' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter services..."
                value={filters.services ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, services: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.services.length} / {details.services.length}</span>
            </div>
            <DataTable columns={serviceColumns} data={filtered.services} keyExtractor={(s) => s.id} emptyMessage="No services found on this host." />
          </div>
        )}

        {activeTab === 'banners' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter banners..."
                value={filters.banners ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, banners: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.banners.length} / {details.banners.length}</span>
            </div>
            <DataTable columns={bannerColumns} data={filtered.banners} keyExtractor={(b) => b.id} emptyMessage="No banners captured for this host." />
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter findings / severity / CVE..."
                value={filters.vulnerabilities ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, vulnerabilities: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.vulnerabilities.length} / {details.vulnerabilities.length}</span>
            </div>
            <DataTable columns={vulnColumns} data={filtered.vulnerabilities} keyExtractor={(v) => v.id} emptyMessage="No vulnerabilities found for this host." />
          </div>
        )}

        {activeTab === 'cves' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter CVEs..."
                value={filters.cves ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, cves: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.cves.length} / {details.cves.length}</span>
            </div>
            <DataTable columns={cveColumns} data={filtered.cves} keyExtractor={(c) => c.id} emptyMessage="No CVEs mapped to this host." />
          </div>
        )}

        {activeTab === 'exploits' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter exploits..."
                value={filters.exploits ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, exploits: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.exploits.length} / {details.exploits.length}</span>
            </div>
            <DataTable columns={exploitColumns} data={filtered.exploits} keyExtractor={(e) => e.id} emptyMessage="No exploits mapped to this host." />
          </div>
        )}

        {activeTab === 'evidence' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter evidence..."
                value={filters.evidence ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, evidence: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.evidence.length} / {details.evidence.length}</span>
            </div>
            <DataTable columns={evidenceColumns} data={filtered.evidence} keyExtractor={(ev) => ev.id} emptyMessage="No captured evidence for this host." />
          </div>
        )}

        {activeTab === 'scan_history' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter scans..."
                value={filters.scan_history ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, scan_history: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.scan_history.length} / {details.scan_history.length}</span>
            </div>
            <DataTable columns={scanColumns} data={filtered.scan_history} keyExtractor={(s) => s.id} emptyMessage="No scans have discovered this host yet." />
          </div>
        )}

        {activeTab === 'reports' && (
          <div className="pt-4 space-y-3">
            <div className="flex items-center justify-between">
              <input
                className="input text-sm w-64"
                placeholder="Filter reports..."
                value={filters.reports ?? ''}
                onChange={(e) => setFilters((f) => ({ ...f, reports: e.target.value }))}
              />
              <span className="text-xs text-surface-400 font-mono">{filtered.reports.length} / {details.reports.length}</span>
            </div>
            <DataTable columns={reportColumns} data={filtered.reports} keyExtractor={(r) => r.id} emptyMessage="No reports generated for this host." />
          </div>
        )}
      </Card>
    </div>
  );
}
