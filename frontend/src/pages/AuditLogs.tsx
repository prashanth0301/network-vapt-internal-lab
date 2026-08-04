import { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { Modal } from '../components/ui/Modal';
import { Table, type Column } from '../components/ui/Table';
import { AuthContext } from '../context/AuthContext';
import { getApiError } from '../services/api';
import { exportAuditLogs, getAuditLogMeta, getAuditLogsPaged } from '../services/auditService';
import type { AuditLog, AuditLogMeta } from '../types/auth';

const PER_PAGE = 10;

const inputClass = 'input w-full';

const ACTION_LABELS: Record<string, string> = {
  login_success: 'Login Succeeded',
  login_failure: 'Login Failed',
  login_locked: 'Account Locked',
  logout: 'Logout',
  token_refresh: 'Token Refresh',
  user_created: 'User Created',
  user_updated: 'User Updated',
  user_deleted: 'User Deleted',
  user_status_changed: 'User Status Changed',
  user_role_changed: 'User Role Changed',
  password_reset: 'Password Reset',
  password_changed: 'Password Changed',
  role_permissions_updated: 'Role Permissions Updated',
  settings_updated: 'Settings Updated',
  session_revoked: 'Session Revoked',
  two_factor_enabled: '2FA Enabled',
  two_factor_disabled: '2FA Disabled',
};

function humanizeAction(action: string): string {
  if (ACTION_LABELS[action]) return ACTION_LABELS[action];
  return action
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5">
      <dt className="text-sm text-surface-500 shrink-0">{label}</dt>
      <dd className="text-sm font-medium text-surface-900 dark:text-surface-100 break-all text-right">
        {value || '—'}
      </dd>
    </div>
  );
}

function oldNewPairs(details: Record<string, unknown>) {
  const entries = Object.entries(details).filter(([key]) => key.startsWith('old_') || key.startsWith('new_'));
  if (entries.length === 0) return null;
  const strip = (k: string) => (k.startsWith('old_') || k.startsWith('new_') ? k.slice(4) : k);
  const grouped = new Map<string, { old?: unknown; new?: unknown }>();
  entries.forEach(([key, value]) => {
    const name = strip(key);
    const group = grouped.get(name) ?? {};
    if (key.startsWith('old_')) group.old = value;
    else group.new = value;
    grouped.set(name, group);
  });
  return Array.from(grouped.entries());
}

function DetailsModal({ log, onClose }: { log: AuditLog | null; onClose: () => void }) {
  return (
    <Modal
      open={log !== null}
      onClose={onClose}
      title={log ? `${humanizeAction(log.action)} — Log Details` : ''}
      size="lg"
    >
      {log && (
        <div>
          <dl className="divide-y divide-surface-200 dark:divide-surface-700">
            <DetailRow label="Timestamp" value={new Date(log.timestamp).toLocaleString()} />
            <DetailRow label="User" value={log.username ?? 'System'} />
            <DetailRow label="Action" value={humanizeAction(log.action)} />
            <DetailRow
              label="Target"
              value={log.resource_type ? `${log.resource_type}${log.resource_id ? ` / ${log.resource_id}` : ''}` : ''}
            />
            <DetailRow label="IP Address" value={log.ip_address ?? ''} />
            <DetailRow label="User Agent" value={log.user_agent ?? ''} />
            <DetailRow label="Status" value={log.status === 'failure' ? 'Failed' : 'Success'} />
          </dl>

          {log.details && (
            <div className="mt-4">
              <p className="text-sm font-medium text-surface-700 dark:text-surface-300 mb-2">
                Details
              </p>
              {oldNewPairs(log.details) ? (
                <div className="rounded-lg border border-surface-200 dark:border-surface-700 overflow-hidden">
                  {oldNewPairs(log.details)!.map(([name, pair]) => (
                    <div key={name} className="flex items-center gap-3 px-4 py-2.5 text-sm border-b border-surface-200 dark:border-surface-700 last:border-b-0">
                      <span className="w-32 shrink-0 font-medium text-surface-600 dark:text-surface-300">
                        {humanizeAction(name)}
                      </span>
                      <span className="flex-1 text-critical line-through decoration-critical/50">
                        {String(pair.old ?? '—')}
                      </span>
                      <span aria-hidden>→</span>
                      <span className="flex-1 text-low">{String(pair.new ?? '—')}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <pre className="rounded-lg bg-surface-50 dark:bg-surface-900 border border-surface-200 dark:border-surface-700 p-3 text-xs text-surface-700 dark:text-surface-300 whitespace-pre-wrap break-all overflow-x-auto max-h-64">
                  {JSON.stringify(log.details, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

export function AuditLogs() {
  const { hasPermission } = useContext(AuthContext);
  const canView = hasPermission('view:audit');

  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [sortBy, setSortBy] = useState<'timestamp' | 'action' | 'username'>('timestamp');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [meta, setMeta] = useState<AuditLogMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<'csv' | 'json' | null>(null);
  const [selected, setSelected] = useState<AuditLog | null>(null);

  const searchTimer = useRef<number | null>(null);

  useEffect(() => {
    if (searchTimer.current) window.clearTimeout(searchTimer.current);
    searchTimer.current = window.setTimeout(() => {
      setSearch(searchInput.trim());
      setPage(1);
    }, 350);
    return () => {
      if (searchTimer.current) window.clearTimeout(searchTimer.current);
    };
  }, [searchInput]);

  useEffect(() => {
    if (canView) {
      getAuditLogMeta()
        .then((res) => setMeta(res.data))
        .catch(() => setMeta(null));
    }
  }, [canView]);

  useEffect(() => {
    setPage(1);
  }, [userFilter, actionFilter, statusFilter, dateFrom, dateTo]);

  const fetchLogs = useCallback(async () => {
    if (!canView) return;
    setLoading(true);
    setError(null);
    try {
      const res = await getAuditLogsPaged({
        search: search || undefined,
        user: userFilter || undefined,
        action: actionFilter || undefined,
        status: statusFilter || undefined,
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
        page,
        per_page: PER_PAGE,
      });
      setLogs(res.data);
      setTotal(res.pagination.total);
      setTotalPages(res.pagination.total_pages);
      if (res.data.length === 0 && page > 1) {
        setPage(Math.max(1, page - 1));
      }
    } catch (err) {
      setError(getApiError(err));
    } finally {
      setLoading(false);
    }
  }, [canView, search, userFilter, actionFilter, statusFilter, dateFrom, dateTo, sortBy, sortOrder, page]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const handleExport = async (format: 'csv' | 'json') => {
    setExporting(format);
    try {
      await exportAuditLogs(format, {
        search: search || undefined,
        user: userFilter || undefined,
        action: actionFilter || undefined,
        status: statusFilter || undefined,
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
      });
    } catch (err) {
      setError(getApiError(err));
    } finally {
      setExporting(null);
    }
  };

  const columns = useMemo<Column<AuditLog>[]>(
    () => [
      {
        key: 'timestamp',
        header: 'Timestamp',
        render: (log) => (
          <span className="text-xs text-surface-500">{new Date(log.timestamp).toLocaleString()}</span>
        ),
      },
      {
        key: 'user',
        header: 'User',
        render: (log) => (
          <span className="font-medium text-surface-900 dark:text-surface-100">
            {log.username ?? 'System'}
          </span>
        ),
      },
      {
        key: 'action',
        header: 'Action',
        render: (log) => (
          <span title={log.action} className="text-surface-700 dark:text-surface-300">
            {humanizeAction(log.action)}
          </span>
        ),
      },
      {
        key: 'target',
        header: 'Target',
        render: (log) =>
          log.resource_type ? (
            <div>
              <span className="text-surface-700 dark:text-surface-300">{log.resource_type}</span>
              {log.resource_id && (
                <div className="text-xs text-surface-500 truncate max-w-40" title={log.resource_id}>
                  {log.resource_id}
                </div>
              )}
            </div>
          ) : (
            <span className="text-surface-400">—</span>
          ),
      },
      {
        key: 'ip',
        header: 'IP Address',
        render: (log) => (
          <span className="text-xs text-surface-500">{log.ip_address ?? '—'}</span>
        ),
      },
      {
        key: 'status',
        header: 'Status',
        render: (log) => (
          <Badge variant={log.status === 'success' ? 'success' : 'danger'}>
            {log.status === 'success' ? 'Success' : 'Failure'}
          </Badge>
        ),
      },
      {
        key: 'actions',
        header: '',
        align: 'right',
        render: (log) => (
          <Button variant="ghost" size="sm" onClick={() => setSelected(log)}>
            Details
          </Button>
        ),
      },
    ],
    [],
  );

  if (!canView) {
    return (
      <Card title="Audit Logs">
        <p className="text-sm text-surface-500">
          You do not have permission to view audit logs. Contact an administrator to request
          access.
        </p>
      </Card>
    );
  }

  const start = total === 0 ? 0 : (page - 1) * PER_PAGE + 1;
  const end = Math.min(page * PER_PAGE, total);

  return (
    <div className="space-y-6">
      <Card
        title="Audit Logs"
        subtitle={`${total} event${total === 1 ? '' : 's'}`}
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" loading={exporting === 'csv'} onClick={() => handleExport('csv')}>
              Export CSV
            </Button>
            <Button variant="secondary" size="sm" loading={exporting === 'json'} onClick={() => handleExport('json')}>
              Export JSON
            </Button>
            <Button variant="ghost" size="sm" onClick={fetchLogs}>
              Refresh
            </Button>
          </div>
        }
      >
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <input
            className={`${inputClass} max-w-xs`}
            placeholder="Search user, action, target, IP..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <select
            className={`${inputClass} w-auto`}
            value={userFilter}
            onChange={(e) => setUserFilter(e.target.value)}
            aria-label="Filter by user"
          >
            <option value="">All Users</option>
            {(meta?.users ?? []).map((u) => (
              <option key={u} value={u}>
                {u}
              </option>
            ))}
          </select>
          <select
            className={`${inputClass} w-auto`}
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            aria-label="Filter by action"
          >
            <option value="">All Actions</option>
            {(meta?.actions ?? []).map((a) => (
              <option key={a} value={a}>
                {humanizeAction(a)}
              </option>
            ))}
          </select>
          <select
            className={`${inputClass} w-auto`}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by status"
          >
            <option value="">All Statuses</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
          </select>
          <label className="flex items-center gap-1 text-xs text-surface-500">
            From
            <input
              type="date"
              className="input w-auto"
              value={dateFrom}
              onChange={(e) => setDateFrom(e.target.value)}
              aria-label="Date from"
            />
          </label>
          <label className="flex items-center gap-1 text-xs text-surface-500">
            To
            <input
              type="date"
              className="input w-auto"
              value={dateTo}
              onChange={(e) => setDateTo(e.target.value)}
              aria-label="Date to"
            />
          </label>
          <select
            className={`${inputClass} w-auto`}
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'timestamp' | 'action' | 'username')}
            aria-label="Sort by"
          >
            <option value="timestamp">Sort: Time</option>
            <option value="action">Sort: Action</option>
            <option value="username">Sort: User</option>
          </select>
          <Button
            variant="ghost"
            size="sm"
            title={sortOrder === 'desc' ? 'Newest first' : 'Oldest first'}
            onClick={() => setSortOrder((o) => (o === 'desc' ? 'asc' : 'desc'))}
          >
            {sortOrder === 'desc' ? '↓ Newest' : '↑ Oldest'}
          </Button>
          {error && <span className="text-sm text-critical">{error}</span>}
        </div>

        <Table
          columns={columns}
          data={logs}
          keyExtractor={(log) => log.id}
          loading={loading}
          emptyMessage="No audit events match the current filters"
        />

        <div className="flex items-center justify-between mt-4 pt-4 border-t border-surface-200 dark:border-surface-700">
          <span className="text-xs text-surface-500">
            Showing {start}–{end} of {total}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              disabled={page <= 1 || loading}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
            >
              Previous
            </Button>
            <span className="text-xs text-surface-500">
              Page {page} of {totalPages}
            </span>
            <Button
              variant="secondary"
              size="sm"
              disabled={page >= totalPages || loading}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            >
              Next
            </Button>
          </div>
        </div>
      </Card>

      <DetailsModal log={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
