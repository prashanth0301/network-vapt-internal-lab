import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';

import { Breadcrumbs } from './Breadcrumbs';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { ToastContainer } from './Toast';

const pageTitles: Record<string, string> = {
  '/': 'Dashboard',
  '/workspace': 'Assessment Workspace',
  '/hosts': 'Host Discovery',
  '/scanning': 'Port Scanner',
  '/vulnerabilities': 'Vulnerability Assessment',
  '/exploitation': 'Exploitation',
  '/packets': 'Packet Analysis',
  '/reports': 'Reports',
  '/settings': 'Settings',
};

const breadcrumbMap: Record<string, { label: string; path?: string }[]> = {
  '/': [{ label: 'Dashboard' }],
  '/workspace': [{ label: 'Workspace', path: '/workspace' }],
  '/hosts': [{ label: 'Hosts', path: '/hosts' }],
  '/scanning': [{ label: 'Port Scanner', path: '/scanning' }],
  '/vulnerabilities': [{ label: 'Vulnerabilities', path: '/vulnerabilities' }],
  '/exploitation': [{ label: 'Exploitation', path: '/exploitation' }],
  '/packets': [{ label: 'Packet Analysis', path: '/packets' }],
  '/reports': [{ label: 'Reports', path: '/reports' }],
  '/settings': [{ label: 'Settings', path: '/settings' }],
};

export function DashboardLayout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const location = useLocation();

  const title = pageTitles[location.pathname] || 'Dashboard';
  const breadcrumbs = breadcrumbMap[location.pathname] || [
    { label: title },
  ];

  return (
    <div className="min-h-screen bg-surface-50 dark:bg-surface-950">
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
      />

      <div
        className={`transition-all duration-300 ${
          sidebarCollapsed ? 'ml-16' : 'ml-60'
        }`}
      >
        <Header title={title} />

        <div className="px-6 pt-4 pb-2">
          <Breadcrumbs items={breadcrumbs} />
        </div>

        <main className="p-6">
          <Outlet />
        </main>
      </div>

      <ToastContainer />
    </div>
  );
}
