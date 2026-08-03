import { useEffect, useState } from 'react';
import { Badge } from './ui/Badge';
import { Button } from './ui/Button';
import { LoadingSpinner } from './ui/LoadingSpinner';
import { Modal } from './ui/Modal';
import type { CVE } from '../types/cve';
import { getCVEById } from '../services/cveService';

interface CVEDetailModalProps {
  cveId: string | null;
  open: boolean;
  onClose: () => void;
}

function severityBadge(severity: string | null): 'danger' | 'warning' | 'info' | 'default' {
  switch (severity) {
    case 'Critical': return 'danger';
    case 'High': return 'warning';
    case 'Medium': return 'info';
    case 'Low': return 'info';
    default: return 'default';
  }
}

export function CVEDetailModal({ cveId, open, onClose }: CVEDetailModalProps) {
  const [cve, setCve] = useState<CVE | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || !cveId) {
      setCve(null);
      return;
    }
    setLoading(true);
    setError(null);
    getCVEById(cveId)
      .then((res) => setCve(res.data))
      .catch(() => setError('Failed to load CVE details'))
      .finally(() => setLoading(false));
  }, [cveId, open]);

  return (
    <Modal open={open} onClose={onClose} size="lg">
      {loading ? (
        <LoadingSpinner size="md" text="Loading CVE details..." />
      ) : error ? (
        <div className="text-center py-8">
          <p className="text-critical mb-3">{error}</p>
          <Button variant="ghost" onClick={onClose}>Close</Button>
        </div>
      ) : cve ? (
        <div className="space-y-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <h4 className="text-lg font-semibold font-mono text-surface-900 dark:text-surface-100">
                {cve.cve_id}
              </h4>
              {cve.vendor && (
                <p className="text-sm text-surface-400 mt-1">
                  {cve.vendor}{cve.product ? ` / ${cve.product}` : ''}
                </p>
              )}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <Badge variant={severityBadge(cve.cvss_severity)}>{cve.cvss_severity || 'N/A'}</Badge>
              {cve.kev_status && <Badge variant="danger">KEV</Badge>}
              {cve.remediation_priority && (
                <Badge variant={cve.remediation_priority === 'Critical' ? 'danger' : cve.remediation_priority === 'High' ? 'warning' : 'info'}>
                  {cve.remediation_priority}
                </Badge>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">CVSS Score</p>
              <p className="font-semibold text-surface-900 dark:text-surface-100">{cve.cvss_score ?? '—'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">CVSS v3</p>
              <p className="font-semibold text-surface-900 dark:text-surface-100">{cve.cvss_v3 ?? '—'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">EPSS</p>
              <p className="font-semibold text-surface-900 dark:text-surface-100">{cve.epss_score != null ? `${(cve.epss_score * 100).toFixed(1)}%` : '—'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">Published</p>
              <p className="text-surface-700 dark:text-surface-300">{cve.published_date || '—'}</p>
            </div>
          </div>

          {cve.description && (
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">Description</p>
              <p className="text-sm text-surface-700 dark:text-surface-300 whitespace-pre-wrap">{cve.description}</p>
            </div>
          )}

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">Base Score</p>
              <p className="text-surface-700 dark:text-surface-300">{cve.base_score ?? '—'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">Exploitability</p>
              <p className="text-surface-700 dark:text-surface-300">{cve.exploitability_score ?? '—'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">Impact</p>
              <p className="text-surface-700 dark:text-surface-300">{cve.impact_score ?? '—'}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">CWE</p>
              <p className="font-mono text-xs text-surface-600 dark:text-surface-400">{cve.cwe_id || '—'}</p>
            </div>
          </div>

          {cve.cvss_vector && (
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">CVSS Vector</p>
              <p className="font-mono text-xs bg-surface-50 dark:bg-surface-900 p-2 rounded text-surface-600 dark:text-surface-400 break-all">{cve.cvss_vector}</p>
            </div>
          )}

          {cve.affected_versions && cve.affected_versions.length > 0 && (
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">Affected Versions</p>
              <div className="flex flex-wrap gap-1">
                {cve.affected_versions.map((v) => (
                  <span key={v} className="inline-block px-2 py-0.5 rounded text-xs bg-surface-100 dark:bg-surface-700 text-surface-700 dark:text-surface-300">
                    {v}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="rounded-lg border border-surface-200 dark:border-surface-700 p-4">
            <div className="flex items-center justify-between">
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">Exploit Available</p>
              <Badge variant={cve.exploit_available ? 'success' : 'default'}>
                {cve.exploit_available ? 'Yes' : 'No'}
              </Badge>
            </div>
            {cve.exploit_available && (
              <p className="text-sm text-surface-700 dark:text-surface-300 mt-2">
                {cve.metasploit_module
                  ? <>Metasploit: <span className="font-mono">{cve.metasploit_module}</span></>
                  : 'Public exploit identified by the exploit verification stage'}
              </p>
            )}
          </div>

          {cve.reference_urls && cve.reference_urls.length > 0 && (
            <div>
              <p className="text-xs font-medium text-surface-400 uppercase mb-1">References</p>
              <ul className="space-y-1">
                {cve.reference_urls.map((ref, i) => (
                  <li key={i}>
                    <a href={ref} target="_blank" rel="noopener noreferrer" className="text-sm text-primary-500 hover:underline break-all">
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="text-xs text-surface-400">
            Source: {cve.source || 'N/A'} · KEV: {cve.kev_status ? 'Yes' : 'No'} · Last Modified: {cve.last_modified || 'N/A'}
          </div>
        </div>
      ) : null}
    </Modal>
  );
}
