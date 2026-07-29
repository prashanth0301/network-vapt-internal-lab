import { useEffect, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { ProgressBar } from '../components/ui/ProgressBar';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { getPorts, startPortScan } from '../services/portService';
import { getHosts } from '../services/hostService';
import type { Port } from '../types/port';
import type { Host } from '../types/host';

export function Scanning() {
  const [ports, setPorts] = useState<Port[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [target, setTarget] = useState('192.168.56.0/24');
  const [scanType, setScanType] = useState('tcp_syn');
  const [scanProfile, setScanProfile] = useState('top_ports');
  const [customPorts, setCustomPorts] = useState('22,80,443');
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    Promise.all([getPorts(), getHosts()])
      .then(([portsRes, hostsRes]) => {
        setPorts(portsRes.data);
        setHosts(hostsRes.data);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const handleStartScan = async () => {
    setScanning(true);
    try {
      await startPortScan({
        target,
        scan_type: scanType as 'tcp_syn' | 'tcp_connect' | 'udp_scan',
        scan_profile: scanProfile as 'top_ports' | 'custom_range' | 'all_ports',
        ports: scanProfile === 'custom_range' ? customPorts : undefined,
      });
      setTimeout(() => {
        getPorts().then((res) => setPorts(res.data)).catch(() => {});
        setScanning(false);
      }, 2000);
    } catch {
      setScanning(false);
    }
  };

  const openPorts = ports.filter((p) => p.state === 'open');
  const stateCounts = {
    open: openPorts.length,
    filtered: ports.filter((p) => p.state === 'filtered').length,
    closed: ports.filter((p) => p.state === 'closed').length,
  };

  return (
    <div className="space-y-6">
      <Card title="Port Scanner Configuration">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Target</label>
            <input
              type="text"
              className="input font-mono w-full"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Scan Type</label>
            <select className="input w-full" value={scanType} onChange={(e) => setScanType(e.target.value)}>
              <option value="tcp_syn">TCP SYN Scan (-sS)</option>
              <option value="tcp_connect">TCP Connect Scan (-sT)</option>
              <option value="udp_scan">UDP Scan (-sU)</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Profile</label>
            <select className="input w-full" value={scanProfile} onChange={(e) => setScanProfile(e.target.value)}>
              <option value="top_ports">Top 1000 Ports</option>
              <option value="custom_range">Custom Range</option>
              <option value="all_ports">All Ports (1-65535)</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
              {scanProfile === 'custom_range' ? 'Port Range' : 'Hosts'}
            </label>
            {scanProfile === 'custom_range' ? (
              <input
                type="text"
                className="input font-mono w-full"
                value={customPorts}
                onChange={(e) => setCustomPorts(e.target.value)}
              />
            ) : (
              <div className="h-10 flex items-center text-sm text-surface-500">
                {hosts.filter((h) => h.is_alive).length} alive hosts
              </div>
            )}
          </div>
        </div>
        <div className="flex gap-3">
          <Button variant="primary" onClick={handleStartScan} disabled={scanning}>
            {scanning ? 'Scanning...' : 'Start Scan'}
          </Button>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="Open Ports" subtitle="Accessible services">
          <div className="text-3xl font-bold text-low">{stateCounts.open}</div>
        </Card>
        <Card title="Filtered" subtitle="Firewall protected">
          <div className="text-3xl font-bold text-warning">{stateCounts.filtered}</div>
        </Card>
        <Card title="Total Scanned" subtitle="All port records">
          <div className="text-3xl font-bold">{ports.length}</div>
        </Card>
      </div>

      {scanning && (
        <Card title="Active Scan" subtitle="Port scan in progress">
          <div className="mb-2 flex justify-between">
            <span className="text-sm font-medium text-surface-700 dark:text-surface-300">Scanning {target}</span>
            <Badge variant="warning">Running</Badge>
          </div>
          <ProgressBar value={45} color="primary" showLabel />
        </Card>
      )}

      <Card title="Scan Results" subtitle="Discovered ports and services">
        {loading ? (
          <LoadingSpinner size="sm" text="Loading port data..." />
        ) : ports.length === 0 ? (
          <div className="text-center py-8 text-surface-400">
            No ports found. Run a scan to discover open ports.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-200 dark:border-surface-700">
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Port</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Protocol</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">State</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Service</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Product</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Version</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                {ports.map((p) => (
                  <tr key={p.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                    <td className="px-4 py-3 font-mono font-medium text-surface-900 dark:text-surface-100">{p.port}</td>
                    <td className="px-4 py-3 uppercase text-xs text-surface-500">{p.protocol}</td>
                    <td className="px-4 py-3">
                      <Badge variant={p.state === 'open' ? 'success' : p.state === 'filtered' ? 'warning' : 'default'}>
                        {p.state}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-surface-600 dark:text-surface-400">
                      {p.services[0]?.name || '—'}
                    </td>
                    <td className="px-4 py-3 text-surface-600 dark:text-surface-400">
                      {p.services[0]?.product || '—'}
                    </td>
                    <td className="px-4 py-3 text-surface-600 dark:text-surface-400">
                      {p.services[0]?.version || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
