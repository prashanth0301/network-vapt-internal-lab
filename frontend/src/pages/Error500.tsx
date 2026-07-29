import { Link } from 'react-router-dom';

export function Error500() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh]">
      <div className="text-8xl font-bold text-critical/20">
        500
      </div>
      <h2 className="text-2xl font-semibold text-surface-900 dark:text-surface-100 mt-4">
        Internal Server Error
      </h2>
      <p className="text-surface-500 dark:text-surface-400 mt-2 text-center max-w-md">
        An unexpected error occurred. Please try again or contact support if the issue persists.
      </p>
      <div className="flex gap-4 mt-6">
        <button
          onClick={() => window.location.reload()}
          className="btn bg-surface-100 dark:bg-surface-700 text-surface-700 dark:text-surface-200 hover:bg-surface-200 dark:hover:bg-surface-600"
        >
          Retry
        </button>
        <Link
          to="/"
          className="btn bg-primary-600 text-white hover:bg-primary-700"
        >
          Return to Dashboard
        </Link>
      </div>
    </div>
  );
}
