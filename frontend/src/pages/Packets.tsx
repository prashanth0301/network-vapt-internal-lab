import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';

const captures = [
  { id: '1', filename: 'arp-discovery.pcap', size: '1.2 MB', packets: 152, duration: '30s', date: '2026-07-28 14:30', status: 'completed' },
  { id: '2', filename: 'exploit-vsftpd.pcap', size: '4.5 MB', packets: 843, duration: '120s', date: '2026-07-28 14:32', status: 'completed' },
  { id: '3', filename: 'eternalblue-traffic.pcap', size: '8.1 MB', packets: 2104, duration: '180s', date: '2026-07-28 15:00', status: 'capturing' },
];

const protocolStats = [
  { protocol: 'TCP', percentage: 62, packets: 1920 },
  { protocol: 'UDP', percentage: 18, packets: 558 },
  { protocol: 'ARP', percentage: 12, packets: 372 },
  { protocol: 'ICMP', percentage: 5, packets: 155 },
  { protocol: 'DNS', percentage: 3, packets: 93 },
];

export function Packets() {
  return (
    <div className="space-y-6">
      <Card title="Packet Capture" subtitle="Live traffic analysis on the lab network">
        <div className="flex gap-3 mb-6">
          <Button variant="primary">Start Capture</Button>
          <Button variant="danger">Stop Capture</Button>
          <Button variant="secondary">Upload PCAP</Button>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Active Capture" subtitle="Interface: eth0 (192.168.56.0/24)">
          {captures.filter(c => c.status === 'capturing').length > 0 ? (
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="w-2 h-2 rounded-full bg-critical animate-pulse" />
                <span className="text-sm font-medium text-surface-700 dark:text-surface-300">Capturing...</span>
              </div>
              <div className="h-2 bg-surface-200 dark:bg-surface-700 rounded-full overflow-hidden">
                <div className="h-full bg-critical rounded-full w-[45%] transition-all" />
              </div>
              <p className="text-xs text-surface-400 mt-2">4,721 packets captured</p>
            </div>
          ) : (
            <p className="text-sm text-surface-400">No active capture. Start a new capture or upload a PCAP file.</p>
          )}
        </Card>

        <Card title="Protocol Distribution">
          <div className="space-y-3">
            {protocolStats.map((p) => (
              <div key={p.protocol}>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-surface-700 dark:text-surface-300">{p.protocol}</span>
                  <span className="text-surface-400">{p.percentage}% ({p.packets} pkts)</span>
                </div>
                <div className="h-1.5 bg-surface-200 dark:bg-surface-700 rounded-full overflow-hidden">
                  <div className="h-full bg-primary-500 rounded-full" style={{ width: `${p.percentage}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card title="Capture History">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-200 dark:border-surface-700">
                <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Filename</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Size</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Packets</th>
                <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Duration</th>
                <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Status</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
              {captures.map((cap) => (
                <tr key={cap.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                  <td className="px-4 py-3 font-mono text-xs text-surface-900 dark:text-surface-100">{cap.filename}</td>
                  <td className="px-4 py-3 text-right text-surface-600 dark:text-surface-400">{cap.size}</td>
                  <td className="px-4 py-3 text-right text-surface-600 dark:text-surface-400">{cap.packets}</td>
                  <td className="px-4 py-3 text-center text-surface-600 dark:text-surface-400">{cap.duration}</td>
                  <td className="px-4 py-3 text-center">
                    <Badge variant={cap.status === 'completed' ? 'success' : cap.status === 'capturing' ? 'warning' : 'default'}>
                      {cap.status}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Button variant="ghost" size="sm">Analyze</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
