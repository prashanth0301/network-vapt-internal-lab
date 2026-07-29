import type { ReactNode } from 'react';

import { classNames } from '../../utils/helpers';

interface CardProps {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  hover?: boolean;
  padding?: boolean;
}

export function Card({
  title,
  subtitle,
  action,
  children,
  className,
  hover = false,
  padding = true,
}: CardProps) {
  return (
    <div className={classNames(hover ? 'card-hover' : 'card', className)}>
      {(title || action) && (
        <div className="flex items-center justify-between px-6 py-4 border-b border-surface-200 dark:border-surface-700">
          <div>
            {title && (
              <h3 className="text-lg font-semibold text-surface-900 dark:text-surface-100">
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="text-sm text-surface-500 dark:text-surface-400 mt-0.5">
                {subtitle}
              </p>
            )}
          </div>
          {action && <div>{action}</div>}
        </div>
      )}
      <div className={classNames(padding && 'p-6')}>{children}</div>
    </div>
  );
}
