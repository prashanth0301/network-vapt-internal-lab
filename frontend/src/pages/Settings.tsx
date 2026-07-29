import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';

export function Settings() {
  return (
    <div className="space-y-6 max-w-3xl">
      <Card title="Network Configuration" subtitle="Target network and scope settings">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Target Subnet</label>
            <input type="text" className="input font-mono" defaultValue="192.168.56.0/24" />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Exclude Hosts</label>
            <input type="text" className="input font-mono" placeholder="192.168.56.1, 192.168.56.10" />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Scan Interface</label>
            <select className="input">
              <option>eth0 (192.168.56.10)</option>
              <option>wlan0</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Ping Sweep Type</label>
            <select className="input">
              <option>ICMP Echo (-sn)</option>
              <option>ARP Scan (-PR)</option>
              <option>TCP SYN to 443 (-PS443)</option>
            </select>
          </div>
        </div>
      </Card>

      <Card title="Scanner Configuration" subtitle="Nmap and vulnerability scanner settings">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Nmap Timing Template</label>
            <select className="input">
              <option value="T3">Normal (T3)</option>
              <option value="T4">Aggressive (T4)</option>
              <option value="T5">Insane (T5)</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Max Port Scan Rate</label>
            <input type="number" className="input" defaultValue={1000} />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Vulnerability Scanner</label>
            <select className="input">
              <option>OpenVAS</option>
              <option>Nessus</option>
              <option>Disabled</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">CVE Database</label>
            <select className="input">
              <option>NVD (Online)</option>
              <option>Local Cache</option>
            </select>
          </div>
        </div>
      </Card>

      <Card title="Tool Paths" subtitle="Security tool executable locations">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Nmap Path</label>
            <input type="text" className="input font-mono" defaultValue="/usr/bin/nmap" />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">TShark Path</label>
            <input type="text" className="input font-mono" defaultValue="/usr/bin/tshark" />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">MSF RPC Host</label>
            <input type="text" className="input font-mono" defaultValue="127.0.0.1:55553" />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">OpenVAS Socket</label>
            <input type="text" className="input font-mono" defaultValue="/var/run/openvassd.sock" />
          </div>
        </div>
      </Card>

      <div className="flex justify-end gap-3">
        <Button variant="secondary">Reset to Defaults</Button>
        <Button variant="primary">Save Settings</Button>
      </div>
    </div>
  );
}
