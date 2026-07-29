export function classNames(...classes: (string | boolean | undefined | null)[]): string {
  return classes.filter(Boolean).join(' ');
}

export function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-IN', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatNumber(num: number): string {
  if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
  if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
  return num.toLocaleString();
}

export function truncate(str: string, length: number): string {
  return str.length > length ? `${str.slice(0, length)}...` : str;
}

export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'text-critical bg-critical/10 border-critical/30',
    high: 'text-high bg-high/10 border-high/30',
    medium: 'text-medium bg-medium/10 border-medium/30',
    low: 'text-low bg-low/10 border-low/30',
    info: 'text-info bg-info/10 border-info/30',
  };
  return colors[severity.toLowerCase()] || colors.info;
}

export function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    running: 'text-primary-500 bg-primary-500/10',
    completed: 'text-low bg-low/10',
    failed: 'text-critical bg-critical/10',
    pending: 'text-surface-500 bg-surface-500/10',
    cancelled: 'text-surface-400 bg-surface-400/10',
  };
  return colors[status.toLowerCase()] || colors.pending;
}
