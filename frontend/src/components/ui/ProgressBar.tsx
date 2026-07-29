import { classNames } from '../../utils/helpers';

interface ProgressBarProps {
  value: number;
  max?: number;
  color?: 'primary' | 'success' | 'warning' | 'danger';
  size?: 'sm' | 'md';
  showLabel?: boolean;
  className?: string;
}

export function ProgressBar({
  value,
  max = 100,
  color = 'primary',
  size = 'md',
  showLabel = false,
  className,
}: ProgressBarProps) {
  const percentage = Math.min((value / max) * 100, 100);

  const colors = {
    primary: 'bg-primary-500',
    success: 'bg-low',
    warning: 'bg-medium',
    danger: 'bg-critical',
  };

  const heights = {
    sm: 'h-1.5',
    md: 'h-2.5',
  };

  return (
    <div className={classNames('w-full', className)}>
      {showLabel && (
        <div className="flex justify-between mb-1">
          <span className="text-xs text-surface-500 dark:text-surface-400">
            {value}/{max}
          </span>
          <span className="text-xs font-medium text-surface-700 dark:text-surface-300">
            {Math.round(percentage)}%
          </span>
        </div>
      )}
      <div
        className={classNames(
          'w-full bg-surface-200 dark:bg-surface-700 rounded-full overflow-hidden',
          heights[size],
        )}
      >
        <div
          className={classNames(
            'transition-all duration-500 ease-out rounded-full',
            colors[color],
            heights[size],
          )}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  );
}
