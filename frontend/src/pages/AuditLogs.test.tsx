import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthContext } from '../context/AuthContext';
import { exportAuditLogs, getAuditLogMeta, getAuditLogsPaged } from '../services/auditService';
import type { AuditLog, AuditLogMeta, User } from '../types/auth';
import { AuditLogs } from './AuditLogs';

vi.mock('../services/auditService');

const mockedGetAuditLogsPaged = vi.mocked(getAuditLogsPaged);
const mockedGetAuditLogMeta = vi.mocked(getAuditLogMeta);
const mockedExportAuditLogs = vi.mocked(exportAuditLogs);

function makeLog(overrides: Partial<AuditLog> = {}): AuditLog {
  return {
    id: 'log-1',
    user_id: 'user-1',
    username: 'admin',
    action: 'user_status_changed',
    resource_type: 'user',
    resource_id: 'user-1',
    details: { old_status: 'active', new_status: 'inactive' },
    ip_address: '10.0.0.5',
    user_agent: 'Mozilla/5.0 (Test Browser)',
    status: 'success',
    timestamp: '2026-08-04T10:30:00Z',
    ...overrides,
  };
}

const meta: AuditLogMeta = {
  users: ['admin', 'analyst'],
  actions: ['login_success', 'user_status_changed'],
  statuses: ['success', 'failure'],
};

const user: User = {
  id: 'user-1',
  username: 'admin',
  email: 'admin@example.com',
  full_name: 'Admin User',
  role: 'administrator',
  status: 'active',
  last_login: null,
  is_active: true,
  permissions: ['view:audit'],
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function renderPage({ canView = true } = {}) {
  return render(
    <AuthContext.Provider
      value={{
        user,
        token: 'token',
        isAuthenticated: true,
        isLoading: false,
        loginToken: vi.fn(),
        logout: vi.fn(),
        hasPermission: (permission: string) => permission === 'view:audit' && canView,
        hasRole: () => false,
      }}
    >
      <AuditLogs />
    </AuthContext.Provider>,
  );
}

describe('AuditLogs', () => {
  beforeEach(() => {
    mockedGetAuditLogsPaged.mockReset();
    mockedGetAuditLogMeta.mockReset();
    mockedExportAuditLogs.mockReset();
    mockedGetAuditLogMeta.mockResolvedValue({ data: meta, status: 'success' });
    mockedGetAuditLogsPaged.mockResolvedValue({
      data: [
        makeLog(),
        makeLog({ id: 'log-2', action: 'login_failure', status: 'failure', username: 'analyst', ip_address: '10.0.0.6' }),
      ],
      status: 'success',
      pagination: { page: 1, per_page: 10, total: 2, total_pages: 1 },
    });
  });

  it('renders audit events with user, action, status and details button', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByRole('table')).toBeTruthy());
    const table = within(screen.getByRole('table'));
    expect(table.getByText('User Status Changed')).toBeTruthy();
    expect(table.getByText('Login Failed')).toBeTruthy();
    expect(table.getByText('Success')).toBeTruthy();
    expect(table.getByText('Failure')).toBeTruthy();
    expect(table.getByText('10.0.0.5')).toBeTruthy();
    expect(table.getAllByText('Details')).toHaveLength(2);
    expect(mockedGetAuditLogsPaged).toHaveBeenCalledWith(
      expect.objectContaining({ sort_by: 'timestamp', sort_order: 'desc', page: 1, per_page: 10 }),
    );
  });

  it('shows details modal with old/new values when Details is clicked', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByRole('table')).toBeTruthy());
    fireEvent.click(within(screen.getByRole('table')).getAllByText('Details')[0]);
    expect(screen.getByText(/Log Details/)).toBeTruthy();
    expect(screen.getByText('Mozilla/5.0 (Test Browser)')).toBeTruthy();
    expect(screen.getByText('active')).toBeTruthy();
    expect(screen.getByText('inactive')).toBeTruthy();
  });

  it('debounces search input before refetching', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByPlaceholderText(/Search user/)).toBeTruthy());
    mockedGetAuditLogsPaged.mockClear();
    fireEvent.change(screen.getByPlaceholderText(/Search user/), {
      target: { value: 'admin' },
    });
    await waitFor(
      () =>
        expect(mockedGetAuditLogsPaged).toHaveBeenCalledWith(
          expect.objectContaining({ search: 'admin' }),
        ),
      { timeout: 3000 },
    );
  });

  it('exports CSV and JSON with current filters', async () => {
    mockedExportAuditLogs.mockResolvedValue(undefined);
    renderPage();
    await waitFor(() => expect(screen.getByText('Export CSV')).toBeTruthy());
    fireEvent.click(screen.getByText('Export CSV'));
    await waitFor(() =>
      expect(mockedExportAuditLogs).toHaveBeenCalledWith(
        'csv',
        expect.objectContaining({ status: undefined, user: undefined }),
      ),
    );
    fireEvent.click(screen.getByText('Export JSON'));
    await waitFor(() => expect(mockedExportAuditLogs).toHaveBeenCalledWith('json', expect.anything()));
  });

  it('hides table when user lacks view:audit permission', () => {
    renderPage({ canView: false });
    expect(screen.getByText(/do not have permission to view audit logs/)).toBeTruthy();
    expect(mockedGetAuditLogsPaged).not.toHaveBeenCalled();
  });
});
