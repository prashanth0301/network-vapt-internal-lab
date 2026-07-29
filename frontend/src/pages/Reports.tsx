import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';

const reports = [
  { id: '1', title: 'Full Network Assessment - Executive Summary', type: 'Executive', format: 'PDF', size: '1.4 MB', date: '2026-07-28', status: 'ready' },
  { id: '2', title: 'Full Network Assessment - Technical Report', type: 'Technical', format: 'HTML', size: '3.2 MB', date: '2026-07-28', status: 'ready' },
  { id: '3', title: 'Metasploitable2 Vulnerability Report', type: 'Technical', format: 'Markdown', size: '256 KB', date: '2026-07-27', status: 'ready' },
  { id: '4', title: 'Windows 7 Security Assessment', type: 'Executive', format: 'PDF', size: '890 KB', date: '2026-07-27', status: 'ready' },
];

const reportFormats = [
  { format: 'Executive Summary', desc: 'High-level overview for management', icon: '📋' },
  { format: 'Technical Report', desc: 'Detailed findings with evidence', icon: '🔬' },
  { format: 'Compliance Report', desc: 'Mapping to standards (CIS, NIST)', icon: '📋' },
];

export function Reports() {
  return (
    <div className="space-y-6">
      <Card title="Generate Report" subtitle="Create professional VAPT reports">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {reportFormats.map((rf) => (
            <div key={rf.format} className="p-4 rounded-lg border border-surface-200 dark:border-surface-700 hover:border-primary-500 cursor-pointer transition-colors">
              <span className="text-2xl">{rf.icon}</span>
              <h4 className="font-medium text-surface-900 dark:text-surface-100 mt-2">{rf.format}</h4>
              <p className="text-xs text-surface-400 mt-1">{rf.desc}</p>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Scan Data</label>
            <select className="input">
              <option>Full Network Assessment</option>
              <option>Metasploitable2 Scan</option>
              <option>Windows 7 Scan</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">Format</label>
            <div className="flex gap-2">
              {['HTML', 'PDF', 'MD'].map((fmt) => (
                <label key={fmt} className="flex items-center gap-1 cursor-pointer">
                  <input type="radio" name="format" className="text-primary-500" />
                  <span className="text-sm text-surface-700 dark:text-surface-300">{fmt}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="flex items-end">
            <Button variant="primary">Generate Report</Button>
          </div>
        </div>
      </Card>

      <Card title="Generated Reports">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-200 dark:border-surface-700">
                <th className="text-left px-4 py-3 text-xs font-medium text-surface-500 uppercase">Title</th>
                <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Type</th>
                <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Format</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Size</th>
                <th className="text-right px-4 py-3 text-xs font-medium text-surface-500 uppercase">Date</th>
                <th className="text-center px-4 py-3 text-xs font-medium text-surface-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
              {reports.map((report) => (
                <tr key={report.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                  <td className="px-4 py-3 font-medium text-surface-900 dark:text-surface-100">{report.title}</td>
                  <td className="px-4 py-3 text-center">
                    <Badge variant={report.type === 'Executive' ? 'info' : 'default'}>{report.type}</Badge>
                  </td>
                  <td className="px-4 py-3 text-center font-mono text-xs">{report.format}</td>
                  <td className="px-4 py-3 text-right text-surface-500">{report.size}</td>
                  <td className="px-4 py-3 text-right text-surface-400">{report.date}</td>
                  <td className="px-4 py-3 text-center">
                    <div className="flex justify-center gap-2">
                      <Button variant="ghost" size="sm">View</Button>
                      <Button variant="ghost" size="sm">Download</Button>
                    </div>
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
