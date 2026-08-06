import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthContext } from '../context/AuthContext';
import { getDashboardSummary } from '../services/dashboardService';
import type { DashboardSummary } from '../types';
import type { User } from '../types/auth';
import { Dashboard } from './Dashboard';

vi.mock('../services/dashboardService');
vi.mock('../services/assessmentStore', () => ({
  useAssessmentChangeTick: () => 0,
  getActiveAssessmentId: () => null,
  getActiveAssessmentName: () => null,
  getActiveAssessmentStatus: () => null,
}));

const mockedGetDashboardSummary = vi.mocked(getDashboardSummary);

function makeSummary(overrides: Partial<DashboardSummary> = {}): DashboardSummary {
  return {
    severity_distribution: [],
    vulnerability_trend: [],
    top_open_ports: [],
    service_distribution: [],
    recent_assessments: [
      { id: '1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d', name: 'Internal Lab Assessment', scan_type: 'full_assessment', target: '192.168.188.130', status: 'completed', created_at: '2026-08-04T01:00:00Z' },
    ],
    recent_reports: [],
    top_vulnerable_hosts: [],
    risk_score: { score: 0, level: 'None', total: 0 },
    critical_count: 0,
    exploit_available_count: 0,
    scan_duration_stats: { count: 0, average_seconds: null, min_seconds: null, max_seconds: null },
    activity_timeline: [],
    totals: { vulnerabilities: 0, hosts: 0, open_ports: 0, services: 0, reports: 0, assessments: 1 },
    ...overrides,
  };
}

const user: User = {
  id: 'user-1',
  username: 'admin',
  email: 'admin@example.com',
  full_name: null,
  role: 'administrator',
  status: 'active',
  last_login: null,
  is_active: true,
  permissions: ['view:audit', 'manage:users'],
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthContext.Provider
        value={{
          user,
          token: 'token',
          isAuthenticated: true,
          isLoading: false,
          loginToken: vi.fn(),
          logout: vi.fn(),
          hasPermission: () => true,
          hasRole: () => true,
        }}
      >
        <Dashboard />
      </AuthContext.Provider>
    </MemoryRouter>,
  );
}

describe('Dashboard recent assessments', () => {
  beforeEach(() => {
    mockedGetDashboardSummary.mockReset();
    mockedGetDashboardSummary.mockResolvedValue({ data: makeSummary(), status: 'success' });
  });

  it('renders recent assessment rows as links to the overview page', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText('Internal Lab Assessment')).toBeTruthy());
    const link = screen.getByTitle(/Open overview for Internal Lab Assessment/);
    expect(link.getAttribute('href')).toBe('/history/1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d');
  });
});
