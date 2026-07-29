import { createBrowserRouter, type RouteObject } from 'react-router-dom';

import { DashboardLayout } from '../components/layout/DashboardLayout';
import { Dashboard } from '../pages/Dashboard';
import { Error404 } from '../pages/Error404';
import { Error500 } from '../pages/Error500';
import { Exploitation } from '../pages/Exploitation';
import { Hosts } from '../pages/Hosts';
import { Packets } from '../pages/Packets';
import { Reports } from '../pages/Reports';
import { Scanning } from '../pages/Scanning';
import { Services } from '../pages/Services';
import { Settings } from '../pages/Settings';
import { Vulnerabilities } from '../pages/Vulnerabilities';
import { Workspace } from '../pages/Workspace';

const routes: RouteObject[] = [
  {
    path: '/',
    element: <DashboardLayout />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'workspace', element: <Workspace /> },
      { path: 'hosts', element: <Hosts /> },
      { path: 'services', element: <Services /> },
      { path: 'scanning', element: <Scanning /> },
      { path: 'vulnerabilities', element: <Vulnerabilities /> },
      { path: 'exploitation', element: <Exploitation /> },
      { path: 'packets', element: <Packets /> },
      { path: 'reports', element: <Reports /> },
      { path: 'settings', element: <Settings /> },
      { path: '500', element: <Error500 /> },
      { path: '*', element: <Error404 /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
