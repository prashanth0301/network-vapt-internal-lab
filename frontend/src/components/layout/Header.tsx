import { useTheme } from '../../hooks/useTheme';
import { classNames } from '../../utils/helpers';

interface HeaderProps {
  title: string;
}

export function Header({ title }: HeaderProps) {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="h-16 bg-white dark:bg-surface-900 border-b border-surface-200 dark:border-surface-700 flex items-center justify-between px-6">
      <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100">
        {title}
      </h1>

      <div className="flex items-center gap-3">
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-500 transition-colors"
          title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
        >
          {theme === 'dark' ? (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
          ) : (
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
            </svg>
          )}
        </button>

        <div className="flex items-center gap-2 pl-3 border-l border-surface-200 dark:border-surface-700">
          <div className="w-8 h-8 rounded-full bg-primary-500 flex items-center justify-center text-white text-sm font-medium">
            O
          </div>
          <div className="hidden sm:block">
            <p className="text-sm font-medium text-surface-700 dark:text-surface-300">
              Operator
            </p>
            <p className="text-xs text-surface-400">vapt@lab</p>
          </div>
        </div>
      </div>
    </header>
  );
}
