import { createBrowserRouter, type RouteObject } from 'react-router-dom';

import { DashboardLayout } from '../components/layout/DashboardLayout';
import { ProtectedRoute } from '../components/ProtectedRoute';
import { Dashboard } from '../pages/Dashboard';
import { Error404 } from '../pages/Error404';
import { Error500 } from '../pages/Error500';
import { Exploitation } from '../pages/Exploitation';
import { Exploits } from '../pages/Exploits';
import { History } from '../pages/History';
import { HostDetailsPage } from '../pages/HostDetails';
import { Hosts } from '../pages/Hosts';
import { Login } from '../pages/Login';
import { Packets } from '../pages/Packets';
import { Reports } from '../pages/Reports';
import { Scanning } from '../pages/Scanning';
import { Services } from '../pages/Services';
import { Settings } from '../pages/Settings';
import { Cves } from '../pages/Cves';
import { Users } from '../pages/Users';
import { AuditLogs } from '../pages/AuditLogs';
import { AssessmentOverview } from '../pages/AssessmentOverview';
import { Vulnerabilities } from '../pages/Vulnerabilities';
import { Workspace } from '../pages/Workspace';

const protectedLayout = (element: React.ReactNode) => (
  <ProtectedRoute>{element}</ProtectedRoute>
);

const routes: RouteObject[] = [
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/',
    element: <DashboardLayout />,
    children: [
      { index: true, element: protectedLayout(<Dashboard />) },
      { path: 'workspace', element: protectedLayout(<Workspace />) },
      { path: 'hosts', element: protectedLayout(<Hosts />) },
      { path: 'hosts/:hostId', element: protectedLayout(<HostDetailsPage />) },
      { path: 'services', element: protectedLayout(<Services />) },
      { path: 'scanning', element: protectedLayout(<Scanning />) },
      { path: 'cves', element: protectedLayout(<Cves />) },
      { path: 'vulnerabilities', element: protectedLayout(<Vulnerabilities />) },
      { path: 'history', element: protectedLayout(<History />) },
      { path: 'history/:assessmentId', element: protectedLayout(<AssessmentOverview />) },
      { path: 'exploitation', element: protectedLayout(<Exploitation />) },
      { path: 'exploits', element: protectedLayout(<Exploits />) },
      { path: 'packets', element: protectedLayout(<Packets />) },
      { path: 'reports', element: protectedLayout(<Reports />) },
      { path: 'users', element: protectedLayout(<Users />) },
      { path: 'audit-logs', element: protectedLayout(<AuditLogs />) },
      { path: 'settings', element: protectedLayout(<Settings />) },
      { path: '500', element: <Error500 /> },
      { path: '*', element: <Error404 /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
