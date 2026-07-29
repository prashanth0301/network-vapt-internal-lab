import { useToast } from '../../hooks/useToast';
import { classNames } from '../../utils/helpers';

export function ToastContainer() {
  const { toasts, removeToast } = useToast();

  if (toasts.length === 0) return null;

  const typeStyles = {
    success: 'bg-low/10 border-low/30 text-low',
    error: 'bg-critical/10 border-critical/30 text-critical',
    warning: 'bg-medium/10 border-medium/30 text-medium',
    info: 'bg-info/10 border-info/30 text-info',
  };

  const typeIcons = {
    success: '✓',
    error: '✕',
    warning: '⚠',
    info: 'ℹ',
  };

  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2 max-w-sm">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={classNames(
            'flex items-start gap-3 px-4 py-3 rounded-lg border shadow-lg backdrop-blur-sm animate-slide-in',
            typeStyles[toast.type],
          )}
        >
          <span className="text-lg flex-shrink-0 mt-0.5">
            {typeIcons[toast.type]}
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium">{toast.title}</p>
            {toast.message && (
              <p className="text-xs opacity-80 mt-0.5">{toast.message}</p>
            )}
          </div>
          <button
            onClick={() => removeToast(toast.id)}
            className="flex-shrink-0 opacity-60 hover:opacity-100 transition-opacity"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      ))}
    </div>
  );
}
