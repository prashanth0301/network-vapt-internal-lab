import { SEVERITY_HEX, SEVERITY_ORDER } from './assessmentMeta';

export function SeverityChips({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts || {}).reduce((sum, n) => sum + n, 0);
  if (total === 0) return <span className="text-xs text-surface-400">-</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {SEVERITY_ORDER.filter((s) => (counts[s] || 0) > 0).map((s) => (
        <span
          key={s}
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium"
          style={{ backgroundColor: `${SEVERITY_HEX[s]}1a`, color: SEVERITY_HEX[s] }}
          title={s}
        >
          {s.charAt(0)}
          <span className="font-mono">{counts[s]}</span>
        </span>
      ))}
    </div>
  );
}
