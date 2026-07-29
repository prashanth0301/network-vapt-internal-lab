import type { ReactNode } from 'react';

import { classNames } from '../../utils/helpers';
import { LoadingSpinner } from './LoadingSpinner';

export interface Column<T> {
  key: string;
  header: string;
  render?: (item: T) => ReactNode;
  sortable?: boolean;
  width?: string;
  align?: 'left' | 'center' | 'right';
}

interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T) => string;
  loading?: boolean;
  emptyMessage?: string;
  className?: string;
}

export function Table<T>({
  columns,
  data,
  keyExtractor,
  loading = false,
  emptyMessage = 'No data available',
  className,
}: TableProps<T>) {
  if (loading) {
    return (
      <div className="py-12">
        <LoadingSpinner text="Loading data..." />
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-surface-400 text-sm">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div className={classNames('overflow-x-auto', className)}>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-surface-200 dark:border-surface-700">
            {columns.map((col) => (
              <th
                key={col.key}
                className={classNames(
                  'px-4 py-3 text-xs font-medium text-surface-500 dark:text-surface-400 uppercase tracking-wider',
                  col.align === 'right' && 'text-right',
                  col.align === 'center' && 'text-center',
                  col.width && `w-[${col.width}]`,
                )}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
          {data.map((item) => (
            <tr
              key={keyExtractor(item)}
              className="hover:bg-surface-50 dark:hover:bg-surface-800/50 transition-colors"
            >
              {columns.map((col) => (
                <td
                  key={col.key}
                  className={classNames(
                    'px-4 py-3 text-surface-700 dark:text-surface-300',
                    col.align === 'right' && 'text-right',
                    col.align === 'center' && 'text-center',
                  )}
                >
                  {col.render
                    ? col.render(item)
                    : (item as Record<string, unknown>)[col.key] as ReactNode}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
