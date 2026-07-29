import { useCallback, useContext, useEffect, useState } from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { AuthContext } from '../context/AuthContext';
import type { User } from '../types/auth';
import { getUsers } from '../services/authService';

export function Users() {
  const { user: currentUser } = useContext(AuthContext);
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getUsers();
      setUsers(res.data);
    } catch {
      setError('Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const roleBadge = (role: string): 'danger' | 'warning' | 'info' | 'success' => {
    switch (role) {
      case 'administrator': return 'danger';
      case 'security_analyst': return 'warning';
      case 'viewer': return 'info';
      default: return 'info';
    }
  };

  return (
    <div className="space-y-6">
      <Card title="User Management" subtitle={`${users.length} users`}>
        {error && (
          <div className="p-4 mb-4 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">
            {error}
            <Button variant="ghost" size="xs" className="ml-3" onClick={fetchData}>Retry</Button>
          </div>
        )}

        {loading ? (
          <LoadingSpinner size="md" text="Loading users..." />
        ) : users.length === 0 ? (
          <div className="text-center py-12 text-surface-400">
            <p className="text-lg font-medium mb-1">No users found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-surface-200 dark:border-surface-700">
                  <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase">Username</th>
                  <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase">Email</th>
                  <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase">Full Name</th>
                  <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">Role</th>
                  <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">Status</th>
                  <th className="text-center px-3 py-3 text-xs font-medium text-surface-500 uppercase">Last Login</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                    <td className="px-3 py-3 font-medium text-surface-900 dark:text-surface-100">
                      {u.username}
                      {currentUser?.id === u.id && <span className="ml-2 text-xs text-primary-500">(you)</span>}
                    </td>
                    <td className="px-3 py-3 text-surface-600 dark:text-surface-400">{u.email}</td>
                    <td className="px-3 py-3 text-surface-600 dark:text-surface-400">{u.full_name || '—'}</td>
                    <td className="px-3 py-3 text-center">
                      <Badge variant={roleBadge(u.role)}>{u.role}</Badge>
                    </td>
                    <td className="px-3 py-3 text-center">
                      <Badge variant={u.status === 'active' ? 'success' : 'default'}>{u.status}</Badge>
                    </td>
                    <td className="px-3 py-3 text-center text-xs text-surface-500">
                      {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
