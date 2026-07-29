import { NavLink } from 'react-router-dom';

import { classNames } from '../../utils/helpers';

const navItems = [
  { label: 'Dashboard', path: '/', icon: '⊞' },
  { label: 'Workspace', path: '/workspace', icon: '⚡' },
  { label: 'Hosts', path: '/hosts', icon: '🖥' },
  { label: 'Port Scanner', path: '/scanning', icon: '📡' },
  { label: 'Services', path: '/services', icon: '🔌' },
  { label: 'Vulnerabilities', path: '/vulnerabilities', icon: '⚠' },
  { label: 'Exploitation', path: '/exploitation', icon: '🎯' },
  { label: 'Packet Analysis', path: '/packets', icon: '📦' },
  { label: 'Reports', path: '/reports', icon: '📊' },
  { label: 'Settings', path: '/settings', icon: '⚙' },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  return (
    <aside
      className={classNames(
        'fixed left-0 top-0 h-full bg-white dark:bg-surface-900 border-r border-surface-200 dark:border-surface-700 z-40 transition-all duration-300 flex flex-col',
        collapsed ? 'w-16' : 'w-60',
      )}
    >
      <div className="flex items-center h-16 px-4 border-b border-surface-200 dark:border-surface-700">
        {!collapsed && (
          <span className="text-lg font-bold text-primary-600 dark:text-primary-400 whitespace-nowrap">
            VAPT Platform
          </span>
        )}
        <button
          onClick={onToggle}
          className={classNames(
            'p-1.5 rounded-lg hover:bg-surface-100 dark:hover:bg-surface-800 text-surface-500',
            collapsed && 'mx-auto',
          )}
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
      </div>

      <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              classNames(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary-50 dark:bg-primary-950/50 text-primary-700 dark:text-primary-300'
                  : 'text-surface-600 dark:text-surface-400 hover:bg-surface-100 dark:hover:bg-surface-800 hover:text-surface-900 dark:hover:text-surface-200',
                collapsed && 'justify-center px-2',
              )
            }
            title={item.label}
          >
            <span className="text-lg">{item.icon}</span>
            {!collapsed && <span>{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-surface-200 dark:border-surface-700">
        {!collapsed && (
          <p className="text-xs text-surface-400 text-center">v1.0.0</p>
        )}
      </div>
    </aside>
  );
}
