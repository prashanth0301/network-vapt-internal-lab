import { SEVERITY_HEX, SEVERITY_ORDER } from './assessmentMeta';

interface SeveritySummaryProps {
  counts: Record<string, number>;
  total: number;
}

export function SeveritySummary({ counts, total }: SeveritySummaryProps) {
  if (total <= 0) {
    return <p className="text-sm text-surface-400">No vulnerabilities found in this assessment.</p>;
  }
  return (
    <div className="space-y-2">
      {SEVERITY_ORDER.filter((s) => (counts[s] || 0) > 0).map((s) => {
        const count = counts[s] || 0;
        const pct = (count / total) * 100;
        return (
          <div key={s}>
            <div className="flex items-center justify-between text-sm mb-1">
              <span className="text-surface-700 dark:text-surface-300">{s}</span>
              <span className="font-mono text-surface-500">{count} ({pct.toFixed(0)}%)</span>
            </div>
            <div className="w-full bg-surface-200 dark:bg-surface-700 rounded-full overflow-hidden h-2">
              <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: SEVERITY_HEX[s] }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
