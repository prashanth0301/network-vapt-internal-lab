import { useEffect, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Table, type Column } from '../components/ui/Table';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import type { Host } from '../types/host';
import { getHosts } from '../services/hostService';

const columns: Column<Host>[] = [
  { key: 'ip_address', header: 'IP Address', render: (h) => <span className="font-mono text-sm">{h.ip_address}</span> },
  { key: 'hostname', header: 'Hostname', render: (h) => h.hostname || '—' },
  { key: 'os_name', header: 'Operating System', render: (h) => h.os_name ? `${h.os_name} ${h.os_version || ''}` : '—' },
  { key: 'mac_address', header: 'MAC Address', render: (h) => <span className="font-mono text-xs text-surface-400">{h.mac_address || '—'}</span> },
  {
    key: 'status',
    header: 'Status',
    render: (h) => (
      <Badge variant={h.is_alive ? 'success' : 'default'}>
        {h.is_alive ? 'Alive' : 'Down'}
      </Badge>
    ),
  },
  {
    key: 'latency',
    header: 'Latency',
    align: 'right',
    render: (h) => (h.latency ? `${h.latency.toFixed(1)}ms` : '—'),
  },
];

export function Hosts() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getHosts()
      .then((res) => setHosts(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <Card title="Host Discovery" subtitle="Live hosts in the 192.168.56.0/24 network" action={<Button variant="primary" size="sm" disabled>Run Discovery</Button>}>
        {loading ? (
          <LoadingSpinner size="sm" text="Loading hosts..." />
        ) : (
          <Table
            columns={columns}
            data={hosts}
            keyExtractor={(h) => h.id}
            emptyMessage="No hosts discovered. Run a discovery scan to find live hosts."
          />
        )}
      </Card>
    </div>
  );
}
