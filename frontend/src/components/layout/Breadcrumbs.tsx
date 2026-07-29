import { Link } from 'react-router-dom';

import type { BreadcrumbItem } from '../../types/common';
import { classNames } from '../../utils/helpers';

interface BreadcrumbsProps {
  items: BreadcrumbItem[];
  className?: string;
}

export function Breadcrumbs({ items, className }: BreadcrumbsProps) {
  return (
    <nav className={classNames('flex items-center gap-2 text-sm', className)}>
      {items.map((item, index) => {
        const isLast = index === items.length - 1;
        return (
          <span key={item.label} className="flex items-center gap-2">
            {index > 0 && (
              <svg className="w-4 h-4 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            )}
            {item.path && !isLast ? (
              <Link
                to={item.path}
                className="text-surface-500 dark:text-surface-400 hover:text-primary-600 dark:hover:text-primary-400 transition-colors"
              >
                {item.label}
              </Link>
            ) : (
              <span
                className={classNames(
                  isLast
                    ? 'text-surface-900 dark:text-surface-100 font-medium'
                    : 'text-surface-500 dark:text-surface-400',
                )}
              >
                {item.label}
              </span>
            )}
          </span>
        );
      })}
    </nav>
  );
}
