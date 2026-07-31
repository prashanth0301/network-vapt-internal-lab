import { useContext } from 'react';
import { NavLink } from 'react-router-dom';

import { AuthContext } from '../../context/AuthContext';
import { classNames } from '../../utils/helpers';
import { APP_VERSION } from '../../constants';

const navItems = [
  { label: 'Dashboard', path: '/', icon: '⊞' },
  { label: 'Workspace', path: '/workspace', icon: '⚡' },
  { label: 'Hosts', path: '/hosts', icon: '🖥' },
  { label: 'Port Scanner', path: '/scanning', icon: '📡' },
  { label: 'Services', path: '/services', icon: '🔌' },
  { label: 'Vulnerabilities', path: '/vulnerabilities', icon: '⚠' },
  { label: 'CVE Intelligence', path: '/cves', icon: '🧠' },
  { label: 'History', path: '/history', icon: '📋' },
  { label: 'Exploit Verification', path: '/exploits', icon: '🎯' },
  { label: 'Exploitation', path: '/exploitation', icon: '⚔' },
  { label: 'Packet Analysis', path: '/packets', icon: '📦' },
  { label: 'Reports', path: '/reports', icon: '📊' },
];

const adminItems = [
  { label: 'User Management', path: '/users', icon: '👥' },
  { label: 'Settings', path: '/settings', icon: '⚙' },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { user, logout } = useContext(AuthContext);
  const isAdmin = user?.role === 'administrator';

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

        {isAdmin && <div className="border-t border-surface-200 dark:border-surface-700 my-2 pt-2">
          <p className="px-3 py-1 text-xs font-medium text-surface-400 uppercase tracking-wider">
            {!collapsed && 'Administration'}
          </p>
          {adminItems.map((item) => (
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
        </div>}
      </nav>

      <div className="p-3 border-t border-surface-200 dark:border-surface-700">
        {!collapsed && user && (
          <div className="flex items-center gap-2 mb-2">
            <div className="w-7 h-7 rounded-full bg-primary-100 dark:bg-primary-900 flex items-center justify-center text-xs font-semibold text-primary-600 dark:text-primary-400">
              {user.username.charAt(0).toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium text-surface-700 dark:text-surface-300 truncate">{user.full_name || user.username}</p>
              <p className="text-[10px] text-surface-400 truncate">{user.role}</p>
            </div>
          </div>
        )}
        {!collapsed && (
          <button onClick={logout} className="w-full text-xs text-surface-400 hover:text-critical text-center py-1">
            Sign Out
          </button>
        )}
        {!collapsed && (
          <p className="text-[10px] text-surface-400 text-center mt-1">v{APP_VERSION}</p>
        )}
      </div>
    </aside>
  );
}
