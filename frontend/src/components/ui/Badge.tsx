import type { ReactNode } from 'react';

import { classNames } from '../../utils/helpers';

export type BadgeVariant = 'default' | 'success' | 'warning' | 'danger' | 'info';

interface BadgeProps {
  children: ReactNode;
  variant?: BadgeVariant;
  size?: 'sm' | 'md';
  className?: string;
}

export function Badge({
  children,
  variant = 'default',
  size = 'sm',
  className,
}: BadgeProps) {
  const variants = {
    default: 'bg-surface-100 dark:bg-surface-700 text-surface-700 dark:text-surface-300',
    success: 'bg-low/10 text-low',
    warning: 'bg-medium/10 text-medium',
    danger: 'bg-critical/10 text-critical',
    info: 'bg-info/10 text-info',
  };

  const sizes = {
    sm: 'px-2 py-0.5 text-xs',
    md: 'px-3 py-1 text-sm',
  };

  return (
    <span
      className={classNames(
        'inline-flex items-center font-medium rounded-full',
        variants[variant],
        sizes[size],
        className,
      )}
    >
      {children}
    </span>
  );
}
