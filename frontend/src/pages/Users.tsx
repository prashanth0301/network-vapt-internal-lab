import { useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { Modal } from '../components/ui/Modal';
import { Table, type Column } from '../components/ui/Table';
import { AuthContext } from '../context/AuthContext';
import { useToast } from '../hooks/useToast';
import { getApiError } from '../services/api';
import {
  createUser,
  deleteUser,
  getUsersPaged,
  resetUserPassword,
  updateUser,
  updateUserRole,
  updateUserStatus,
} from '../services/authService';
import type { User } from '../types/auth';
import {
  validateEmail,
  validateFullName,
  validatePassword,
  validatePasswordConfirm,
  validateRole,
  validateUsername,
} from '../utils/userValidation';

const ROLE_LABELS: Record<string, string> = {
  administrator: 'Admin',
  security_analyst: 'Analyst',
  viewer: 'Viewer',
};

const PER_PAGE = 10;

type RoleValue = 'administrator' | 'security_analyst' | 'viewer';
type StatusValue = 'active' | 'inactive' | 'disabled';

const inputClass = 'input w-full';

function RoleBadge({ role }: { role: string }) {
  const variant =
    role === 'administrator' ? 'danger' : role === 'security_analyst' ? 'warning' : 'info';
  return <Badge variant={variant}>{ROLE_LABELS[role] ?? role}</Badge>;
}

function StatusToggle({
  active,
  disabled,
  onChange,
}: {
  active: boolean;
  disabled?: boolean;
  onChange: () => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={active}
      onClick={onChange}
      disabled={disabled}
      title={active ? 'Deactivate user' : 'Activate user'}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
        active ? 'bg-low' : 'bg-surface-300 dark:bg-surface-600'
      } disabled:cursor-not-allowed disabled:opacity-40`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
          active ? 'translate-x-[18px]' : 'translate-x-[3px]'
        }`}
      />
    </button>
  );
}

function FieldError({ message }: { message?: string | null }) {
  if (!message) return null;
  return <p className="mt-1 text-xs text-critical">{message}</p>;
}

export function Users() {
  const { user: currentUser, hasPermission } = useContext(AuthContext);
  const { addToast } = useToast();

  const isAdmin = hasPermission('manage:users');

  const [users, setUsers] = useState<User[]>([]);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<User | null>(null);
  const [resetTarget, setResetTarget] = useState<User | null>(null);

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
    setPage(1);
  }, [statusFilter, roleFilter]);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getUsersPaged({
        search: search || undefined,
        status: statusFilter || undefined,
        role: roleFilter || undefined,
        page,
        per_page: PER_PAGE,
      });
      setUsers(res.data.items);
      setTotal(res.data.total);
      setTotalPages(res.data.total_pages);
      if (res.data.items.length === 0 && page > 1) {
        setPage(Math.max(1, page - 1));
      }
    } catch (err) {
      setError(getApiError(err));
    } finally {
      setLoading(false);
    }
  }, [search, statusFilter, roleFilter, page]);

  useEffect(() => {
    if (isAdmin) fetchUsers();
  }, [fetchUsers, isAdmin]);

  const patchUserInList = (updated: User) => {
    setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
  };

  const handleToggleStatus = async (target: User) => {
    const next: StatusValue = target.status === 'active' ? 'inactive' : 'active';
    setBusyId(target.id);
    try {
      const res = await updateUserStatus(target.id, { status: next });
      patchUserInList(res.data);
      addToast({
        type: 'success',
        title: `${target.username} ${next === 'active' ? 'activated' : 'deactivated'}`,
      });
    } catch (err) {
      addToast({ type: 'error', title: 'Status change failed', message: getApiError(err) });
    } finally {
      setBusyId(null);
    }
  };

  const handleRoleChange = async (target: User, role: string) => {
    if (role === target.role) return;
    setBusyId(target.id);
    try {
      const res = await updateUserRole(target.id, { role: role as RoleValue });
      patchUserInList(res.data);
      addToast({ type: 'success', title: `Role changed to ${ROLE_LABELS[role]}` });
      if (currentUser && target.id === currentUser.id) {
        addToast({
          type: 'info',
          title: 'Your role changed',
          message: 'Reloading to apply the new permissions.',
        });
        window.setTimeout(() => window.location.reload(), 1200);
      }
    } catch (err) {
      addToast({ type: 'error', title: 'Role change failed', message: getApiError(err) });
    } finally {
      setBusyId(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setBusyId(deleteTarget.id);
    try {
      await deleteUser(deleteTarget.id);
      addToast({ type: 'success', title: `User ${deleteTarget.username} deleted` });
      setUsers((prev) => prev.filter((u) => u.id !== deleteTarget.id));
      setTotal((t) => Math.max(0, t - 1));
      setDeleteTarget(null);
    } catch (err) {
      addToast({ type: 'error', title: 'Delete failed', message: getApiError(err) });
      setDeleteTarget(null);
    } finally {
      setBusyId(null);
    }
  };

  const columns = useMemo<Column<User>[]>(
    () => [
      {
        key: 'user',
        header: 'User',
        render: (u) => (
          <div>
            <div className="font-medium text-surface-900 dark:text-surface-100">
              {u.username}
              {currentUser?.id === u.id && (
                <span className="ml-2 text-xs text-primary-500">(you)</span>
              )}
            </div>
            {u.full_name && (
              <div className="text-xs text-surface-500 dark:text-surface-400">{u.full_name}</div>
            )}
          </div>
        ),
      },
      {
        key: 'email',
        header: 'Email',
        render: (u) => <span className="text-surface-600 dark:text-surface-400">{u.email}</span>,
      },
      {
        key: 'role',
        header: 'Role',
        render: (u) => (
          <div className="flex items-center gap-2">
            <RoleBadge role={u.role} />
            <select
              className="input px-2 py-1 text-xs"
              value={u.role}
              disabled={busyId === u.id}
              onChange={(e) => handleRoleChange(u, e.target.value)}
            >
              <option value="administrator">Admin</option>
              <option value="security_analyst">Analyst</option>
              <option value="viewer">Viewer</option>
            </select>
          </div>
        ),
      },
      {
        key: 'status',
        header: 'Status',
        render: (u) => (
          <div className="flex items-center gap-2">
            <StatusToggle
              active={u.status === 'active'}
              disabled={busyId === u.id}
              onChange={() => handleToggleStatus(u)}
            />
            {busyId === u.id ? (
              <LoadingSpinner size="sm" />
            ) : (
              <Badge variant={u.status === 'active' ? 'success' : 'default'}>{u.status}</Badge>
            )}
          </div>
        ),
      },
      {
        key: 'last_login',
        header: 'Last Login',
        render: (u) => (
          <span className="text-xs text-surface-500">
            {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
          </span>
        ),
      },
      {
        key: 'actions',
        header: 'Actions',
        render: (u) => (
          <div className="flex items-center gap-1.5">
            <Button
              variant="ghost"
              size="sm"
              disabled={busyId !== null}
              onClick={() => setEditUser(u)}
            >
              Edit
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={busyId !== null}
              onClick={() => setResetTarget(u)}
            >
              Reset
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="text-critical hover:bg-critical/10"
              disabled={busyId !== null || currentUser?.id === u.id}
              title={currentUser?.id === u.id ? 'You cannot delete your own account' : undefined}
              onClick={() => setDeleteTarget(u)}
            >
              Delete
            </Button>
          </div>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [currentUser, busyId],
  );

  if (!isAdmin) {
    return <SelfProfileView user={currentUser} />;
  }

  const start = total === 0 ? 0 : (page - 1) * PER_PAGE + 1;
  const end = Math.min(page * PER_PAGE, total);

  return (
    <div className="space-y-6">
      <Card
        title="User Management"
        subtitle={`${total} user${total === 1 ? '' : 's'}`}
        action={
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            Create User
          </Button>
        }
      >
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <input
            className={`${inputClass} max-w-xs`}
            placeholder="Search username, email, name..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <select
            className={`${inputClass} w-auto`}
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            aria-label="Filter by status"
          >
            <option value="">All</option>
            <option value="active">Active</option>
            <option value="inactive">Disabled</option>
          </select>
          <select
            className={`${inputClass} w-auto`}
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            aria-label="Filter by role"
          >
            <option value="">All Roles</option>
            <option value="administrator">Admin</option>
            <option value="security_analyst">Analyst</option>
            <option value="viewer">Viewer</option>
          </select>
          {error && (
            <span className="text-sm text-critical">{error}</span>
          )}
        </div>

        <Table
          columns={columns}
          data={users}
          keyExtractor={(u) => u.id}
          loading={loading}
          emptyMessage="No users match the current filters"
        />

        <div className="flex items-center justify-between mt-4 pt-4 border-t border-surface-200 dark:border-surface-700">
          <span className="text-xs text-surface-500">
            Showing {start}–{end} of {total}
          </span>
          <div className="flex items-center gap-2">
            <Button variant="secondary" size="sm" disabled={page <= 1 || loading} onClick={() => setPage((p) => Math.max(1, p - 1))}>
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

      <CreateUserDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onCreated={(user) => {
          setCreateOpen(false);
          addToast({ type: 'success', title: `User ${user.username} created` });
          if (search || statusFilter || roleFilter) {
            setSearch('');
            setSearchInput('');
            setStatusFilter('');
            setRoleFilter('');
          }
          setPage(1);
          fetchUsers();
        }}
      />

      <EditUserDialog
        user={editUser}
        onClose={() => setEditUser(null)}
        onSaved={(user) => {
          setEditUser(null);
          patchUserInList(user);
          addToast({ type: 'success', title: `User ${user.username} updated` });
        }}
      />

      <ResetPasswordDialog
        user={resetTarget}
        onClose={() => setResetTarget(null)}
        onReset={() => {
          setResetTarget(null);
          addToast({ type: 'success', title: 'Password reset successfully' });
        }}
      />

      <DeleteUserDialog
        user={deleteTarget}
        busy={busyId === deleteTarget?.id}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
      />
    </div>
  );
}

function SelfProfileView({ user }: { user: User | null }) {
  if (!user) {
    return (
      <Card title="My Profile">
        <LoadingSpinner size="md" text="Loading profile..." />
      </Card>
    );
  }
  const rows: [string, string][] = [
    ['Username', user.username],
    ['Email', user.email],
    ['Full Name', user.full_name || '—'],
    ['Role', ROLE_LABELS[user.role] ?? user.role],
    ['Status', user.status],
    ['Last Login', user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'],
    ['Account Created', new Date(user.created_at).toLocaleDateString()],
  ];
  return (
    <div className="max-w-xl">
      <Card title="My Profile" subtitle="Your account details">
        <dl className="divide-y divide-surface-200 dark:divide-surface-700">
          {rows.map(([label, value]) => (
            <div key={label} className="flex items-center justify-between py-3">
              <dt className="text-sm text-surface-500">{label}</dt>
              <dd className="text-sm font-medium text-surface-900 dark:text-surface-100">{value}</dd>
            </div>
          ))}
        </dl>
        <p className="mt-4 text-xs text-surface-400">
          Contact an administrator to update your profile or reset your password.
        </p>
      </Card>
    </div>
  );
}

interface DialogProps {
  open: boolean;
  onClose: () => void;
}

function CreateUserDialog({
  open,
  onClose,
  onCreated,
}: DialogProps & { onCreated: (user: User) => void }) {
  const { addToast } = useToast();
  const [form, setForm] = useState({
    username: '',
    email: '',
    full_name: '',
    role: 'viewer' as RoleValue,
    password: '',
    confirm: '',
  });
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (open) {
      setForm({ username: '', email: '', full_name: '', role: 'viewer', password: '', confirm: '' });
      setErrors({});
    }
  }, [open]);

  const set = (key: keyof typeof form, value: string) => {
    setForm((f) => ({ ...f, [key]: value }));
    setErrors((e) => ({ ...e, [key]: null }));
  };

  const validate = () => {
    const next: Record<string, string | null> = {
      username: validateUsername(form.username),
      email: validateEmail(form.email),
      full_name: validateFullName(form.full_name),
      role: validateRole(form.role),
      password: validatePassword(form.password),
      confirm: validatePasswordConfirm(form.password, form.confirm),
    };
    setErrors(next);
    return Object.values(next).every((v) => !v);
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    setSubmitting(true);
    try {
      const res = await createUser({
        username: form.username.trim(),
        email: form.email.trim(),
        full_name: form.full_name.trim() || undefined,
        role: form.role,
        password: form.password,
      });
      onCreated(res.data);
    } catch (err) {
      addToast({ type: 'error', title: 'Create user failed', message: getApiError(err) });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Create User"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button loading={submitting} onClick={handleSubmit}>
            Create User
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium mb-1">Username *</label>
          <input
            className={inputClass}
            value={form.username}
            onChange={(e) => set('username', e.target.value)}
            placeholder="e.g. john_doe"
          />
          <FieldError message={errors.username} />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Email *</label>
          <input
            className={inputClass}
            type="email"
            value={form.email}
            onChange={(e) => set('email', e.target.value)}
            placeholder="e.g. john@example.com"
          />
          <FieldError message={errors.email} />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Full Name</label>
          <input
            className={inputClass}
            value={form.full_name}
            onChange={(e) => set('full_name', e.target.value)}
            placeholder="e.g. John Doe"
          />
          <FieldError message={errors.full_name} />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Role *</label>
          <select
            className={inputClass}
            value={form.role}
            onChange={(e) => set('role', e.target.value)}
          >
            <option value="viewer">Viewer</option>
            <option value="security_analyst">Analyst</option>
            <option value="administrator">Admin</option>
          </select>
          <FieldError message={errors.role} />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Password *</label>
          <input
            className={inputClass}
            type="password"
            value={form.password}
            onChange={(e) => set('password', e.target.value)}
            placeholder="Minimum 8 characters"
          />
          <FieldError message={errors.password} />
        </div>
        <div>
          <label className="block text-sm font-medium mb-1">Confirm Password *</label>
          <input
            className={inputClass}
            type="password"
            value={form.confirm}
            onChange={(e) => set('confirm', e.target.value)}
            placeholder="Re-enter password"
          />
          <FieldError message={errors.confirm} />
        </div>
      </div>
    </Modal>
  );
}

function EditUserDialog({
  user,
  onClose,
  onSaved,
}: {
  user: User | null;
  onClose: () => void;
  onSaved: (user: User) => void;
}) {
  const { addToast } = useToast();
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (user) {
      setEmail(user.email);
      setFullName(user.full_name || '');
      setErrors({});
    }
  }, [user]);

  const handleSubmit = async () => {
    if (!user) return;
    const next = {
      email: validateEmail(email),
      full_name: validateFullName(fullName),
    };
    setErrors(next);
    if (Object.values(next).some((v) => v)) return;
    setSubmitting(true);
    try {
      const res = await updateUser(user.id, {
        email: email.trim(),
        full_name: fullName.trim() || undefined,
      });
      onSaved(res.data);
    } catch (err) {
      addToast({ type: 'error', title: 'Update failed', message: getApiError(err) });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={user !== null}
      onClose={onClose}
      title={user ? `Edit User - ${user.username}` : ''}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button loading={submitting} onClick={handleSubmit}>
            Save Changes
          </Button>
        </>
      }
    >
      {user && (
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Email *</label>
            <input
              className={inputClass}
              type="email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                setErrors((er) => ({ ...er, email: null }));
              }}
            />
            <FieldError message={errors.email} />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Full Name</label>
            <input
              className={inputClass}
              value={fullName}
              onChange={(e) => {
                setFullName(e.target.value);
                setErrors((er) => ({ ...er, full_name: null }));
              }}
            />
            <FieldError message={errors.full_name} />
          </div>
          <p className="text-xs text-surface-400">
            Change the role or status using the controls in the table. Use “Reset” to set a new
            password.
          </p>
        </div>
      )}
    </Modal>
  );
}

function ResetPasswordDialog({
  user,
  onClose,
  onReset,
}: {
  user: User | null;
  onClose: () => void;
  onReset: () => void;
}) {
  const { addToast } = useToast();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [errors, setErrors] = useState<Record<string, string | null>>({});
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (user) {
      setPassword('');
      setConfirm('');
      setErrors({});
    }
  }, [user]);

  const handleSubmit = async () => {
    if (!user) return;
    const next = {
      password: validatePassword(password),
      confirm: validatePasswordConfirm(password, confirm),
    };
    setErrors(next);
    if (Object.values(next).some((v) => v)) return;
    setSubmitting(true);
    try {
      await resetUserPassword(user.id, { password });
      onReset();
    } catch (err) {
      addToast({ type: 'error', title: 'Password reset failed', message: getApiError(err) });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Modal
      open={user !== null}
      onClose={onClose}
      title={user ? `Reset Password - ${user.username}` : ''}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={submitting}>
            Cancel
          </Button>
          <Button loading={submitting} onClick={handleSubmit}>
            Reset Password
          </Button>
        </>
      }
    >
      {user && (
        <div className="space-y-4">
          <p className="text-sm text-surface-500">
            Set a new password for <b>{user.username}</b>. The user will be required to use this
            password at next login.
          </p>
          <div>
            <label className="block text-sm font-medium mb-1">New Password *</label>
            <input
              className={inputClass}
              type="password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                setErrors((er) => ({ ...er, password: null }));
              }}
              placeholder="Minimum 8 characters"
            />
            <FieldError message={errors.password} />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Confirm Password *</label>
            <input
              className={inputClass}
              type="password"
              value={confirm}
              onChange={(e) => {
                setConfirm(e.target.value);
                setErrors((er) => ({ ...er, confirm: null }));
              }}
              placeholder="Re-enter password"
            />
            <FieldError message={errors.confirm} />
          </div>
        </div>
      )}
    </Modal>
  );
}

function DeleteUserDialog({
  user,
  busy,
  onClose,
  onConfirm,
}: {
  user: User | null;
  busy: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Modal
      open={user !== null}
      onClose={onClose}
      title="Delete User"
      size="sm"
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button variant="danger" loading={busy} onClick={onConfirm}>
            Delete
          </Button>
        </>
      }
    >
      {user && (
        <div className="space-y-3">
          <p className="text-sm text-surface-700 dark:text-surface-300">
            Are you sure you want to delete user{' '}
            <b>{user.username}</b>
            {user.full_name ? ` (${user.full_name})` : ''}? This action cannot be undone.
          </p>
          {user.role === 'administrator' && (
            <p className="text-xs text-critical bg-critical/10 border border-critical/20 rounded-lg p-2">
              Note: you cannot delete the last active administrator account.
            </p>
          )}
        </div>
      )}
    </Modal>
  );
}
