import { Link } from 'react-router-dom';

export function Error404() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh]">
      <div className="text-8xl font-bold text-surface-200 dark:text-surface-700">
        404
      </div>
      <h2 className="text-2xl font-semibold text-surface-900 dark:text-surface-100 mt-4">
        Page Not Found
      </h2>
      <p className="text-surface-500 dark:text-surface-400 mt-2 text-center max-w-md">
        The page you are looking for does not exist or has been moved.
      </p>
      <Link
        to="/"
        className="mt-6 btn bg-primary-600 text-white hover:bg-primary-700"
      >
        Return to Dashboard
      </Link>
    </div>
  );
}
