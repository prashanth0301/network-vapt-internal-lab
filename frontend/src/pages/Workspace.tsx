import { useState } from 'react';

import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { ProgressBar } from '../components/ui/ProgressBar';

interface AssessmentStep {
  id: number;
  name: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  icon: string;
}

const defaultSteps: AssessmentStep[] = [
  { id: 1, name: 'Host Discovery', description: 'Nmap ping sweep to identify live hosts', status: 'pending', icon: '🖥' },
  { id: 2, name: 'Port Scanning', description: 'TCP/UDP scan on discovered hosts', status: 'pending', icon: '📡' },
  { id: 3, name: 'Service Enumeration', description: 'Version detection and banner grabbing', status: 'pending', icon: '🔍' },
  { id: 4, name: 'Vulnerability Assessment', description: 'OpenVAS/Nessus vulnerability scan', status: 'pending', icon: '⚠' },
  { id: 5, name: 'CVE Intelligence', description: 'CVE correlation and exploit mapping', status: 'pending', icon: '🧠' },
  { id: 6, name: 'Report Generation', description: 'Generate HTML, PDF, Markdown reports', status: 'pending', icon: '📊' },
];

export function Workspace() {
  const [steps] = useState<AssessmentStep[]>(defaultSteps);
  const [target, setTarget] = useState('192.168.56.0/24');
  const [assessmentName, setAssessmentName] = useState('');

  const completedSteps = steps.filter((s) => s.status === 'completed').length;
  const progress = (completedSteps / steps.length) * 100;

  return (
    <div className="space-y-6">
      <Card title="Assessment Configuration" subtitle="Define and run a full VAPT assessment">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
              Assessment Name
            </label>
            <input
              type="text"
              className="input"
              placeholder="e.g., Internal Lab Assessment Q3"
              value={assessmentName}
              onChange={(e) => setAssessmentName(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
              Target Range
            </label>
            <input
              type="text"
              className="input font-mono"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
        </div>
        <div className="flex gap-3">
          <Button variant="primary" size="lg">
            Start Full Assessment
          </Button>
          <Button variant="secondary" size="lg">
            Custom Assessment
          </Button>
        </div>
      </Card>

      <Card title="Assessment Progress" subtitle="6-step VAPT workflow">
        <div className="mb-6">
          <ProgressBar
            value={progress}
            color={progress === 100 ? 'success' : 'primary'}
            size="md"
            showLabel
          />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {steps.map((step) => (
            <div
              key={step.id}
              className="p-4 rounded-lg border border-surface-200 dark:border-surface-700 bg-surface-50 dark:bg-surface-800/50"
            >
              <div className="flex items-start justify-between mb-2">
                <span className="text-2xl">{step.icon}</span>
                <Badge
                  variant={
                    step.status === 'completed'
                      ? 'success'
                      : step.status === 'running'
                      ? 'warning'
                      : step.status === 'failed'
                      ? 'danger'
                      : 'default'
                  }
                >
                  {step.status}
                </Badge>
              </div>
              <h4 className="font-medium text-surface-900 dark:text-surface-100 text-sm">
                {step.name}
              </h4>
              <p className="text-xs text-surface-400 mt-1">{step.description}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Quick Actions">
        <div className="flex flex-wrap gap-3">
          <Button variant="primary">New Host Discovery</Button>
          <Button variant="secondary">Quick Port Scan</Button>
          <Button variant="secondary">Vulnerability Scan</Button>
          <Button variant="secondary">Generate Report</Button>
        </div>
      </Card>
    </div>
  );
}
