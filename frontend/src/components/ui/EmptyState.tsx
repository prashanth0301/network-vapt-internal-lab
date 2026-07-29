import type { ReactNode } from 'react';

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4">
      {icon && (
        <div className="text-surface-300 dark:text-surface-600 mb-4">
          {icon}
        </div>
      )}
      <h3 className="text-lg font-medium text-surface-900 dark:text-surface-100 mb-1">
        {title}
      </h3>
      {description && (
        <p className="text-sm text-surface-500 dark:text-surface-400 text-center max-w-md mb-6">
          {description}
        </p>
      )}
      {action && <div>{action}</div>}
    </div>
  );
}
