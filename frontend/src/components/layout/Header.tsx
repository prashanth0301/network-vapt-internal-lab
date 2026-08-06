import { useContext, useEffect, useState } from 'react';
import { AuthContext } from '../../context/AuthContext';
import { useTheme } from '../../hooks/useTheme';
import { getAssessments } from '../../services/assessmentService';
import {
  clearActiveAssessment,
  getActiveAssessmentId,
  getActiveAssessmentName,
  setActiveAssessment,
  useAssessmentChangeTick,
} from '../../services/assessmentStore';
import type { Assessment } from '../../types/assessment';

interface HeaderProps {
  title: string;
}

export function Header({ title }: HeaderProps) {
  const { theme, toggleTheme } = useTheme();
  const { user } = useContext(AuthContext);
  const tick = useAssessmentChangeTick();
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [activeId, setActiveId] = useState<string | null>(getActiveAssessmentId());

  useEffect(() => {
    getAssessments({ perPage: 100 })
      .then((res) => setAssessments(res.data || []))
      .catch(() => {});
  }, [tick]);

  const handleChange = (value: string) => {
    if (!value) {
      clearActiveAssessment();
      setActiveId(null);
      return;
    }
    const selected = assessments.find((a) => a.id === value);
    setActiveAssessment(value, selected?.name, selected?.status);
    setActiveId(value);
  };

  const activeName = getActiveAssessmentName();

  return (
    <header className="h-16 bg-white dark:bg-surface-900 border-b border-surface-200 dark:border-surface-700 flex items-center justify-between px-6">
      <h1 className="text-xl font-semibold text-surface-900 dark:text-surface-100">
        {title}
      </h1>

      <div className="flex items-center gap-3">
        <select
          className="input w-56 text-sm"
          value={activeId || ''}
          onChange={(e) => handleChange(e.target.value)}
          title="Selected assessment"
        >
          <option value="">
            {assessments.length === 0 && !activeId ? 'No assessments' : 'All assessments'}
          </option>
          {assessments.map((a) => (
            <option key={a.id} value={a.id}>{a.name}{a.status === 'draft' ? ' (draft)' : ''}</option>
          ))}
        </select>

        {activeId && (
          <span className="hidden lg:block text-xs text-surface-400 max-w-[160px] truncate" title={activeName || undefined}>
            {activeName || 'Assessment selected'}
          </span>
        )}

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
            {user ? user.full_name?.charAt(0)?.toUpperCase() || user.username.charAt(0).toUpperCase() : '?'}
          </div>
          <div className="hidden sm:block">
            <p className="text-sm font-medium text-surface-700 dark:text-surface-300">
              {user?.full_name || user?.username || 'Operator'}
            </p>
            <p className="text-xs text-surface-400">{user?.email || 'vapt@lab'}</p>
          </div>
        </div>
      </div>
    </header>
  );
}
