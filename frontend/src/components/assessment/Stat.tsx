export function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="p-3 rounded-lg bg-surface-50 dark:bg-surface-800/50">
      <p className="text-xs text-surface-500 dark:text-surface-400">{label}</p>
      <p className="text-lg font-semibold text-surface-900 dark:text-surface-100">{value}</p>
    </div>
  );
}
