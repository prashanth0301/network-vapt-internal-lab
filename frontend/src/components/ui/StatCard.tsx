import type { ReactNode } from 'react';

import { classNames } from '../../utils/helpers';

interface StatCardProps {
  title: string;
  value: string | number;
  icon?: ReactNode;
  trend?: { value: number; positive: boolean };
  color?: 'primary' | 'success' | 'warning' | 'danger' | 'info';
  subtitle?: string;
  className?: string;
}

export function StatCard({
  title,
  value,
  icon,
  trend,
  color = 'primary',
  subtitle,
  className,
}: StatCardProps) {
  const colorClasses = {
    primary: 'bg-primary-50 dark:bg-primary-950/50 text-primary-600 dark:text-primary-400',
    success: 'bg-low/10 text-low',
    warning: 'bg-medium/10 text-medium',
    danger: 'bg-critical/10 text-critical',
    info: 'bg-info/10 text-info',
  };

  return (
    <div
      className={classNames(
        'card p-5 flex items-start gap-4',
        className,
      )}
    >
      {icon && (
        <div
          className={classNames(
            'p-3 rounded-lg flex-shrink-0',
            colorClasses[color],
          )}
        >
          {icon}
        </div>
      )}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-surface-500 dark:text-surface-400 truncate">
          {title}
        </p>
        <p className="text-2xl font-bold text-surface-900 dark:text-surface-100 mt-1">
          {value}
        </p>
        {trend && (
          <p
            className={classNames(
              'text-xs mt-1 flex items-center gap-1',
              trend.positive ? 'text-low' : 'text-critical',
            )}
          >
            <span>{trend.positive ? '↑' : '↓'}</span>
            <span>{Math.abs(trend.value)}%</span>
            <span className="text-surface-400">vs last scan</span>
          </p>
        )}
        {subtitle && (
          <p className="text-xs text-surface-400 mt-1">{subtitle}</p>
        )}
      </div>
    </div>
  );
}
