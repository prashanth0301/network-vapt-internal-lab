import { useCallback, useEffect, useState } from 'react';

import { Badge, type BadgeVariant } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import type { ServiceIntelligence } from '../types/service';
import { getCategories, getServices } from '../services/serviceIntelligenceService';
import { getActiveAssessmentId, useAssessmentChangeTick } from '../services/assessmentStore';

function confidenceColor(score: number | null): BadgeVariant {
  if (score === null) return 'default';
  if (score >= 90) return 'success';
  if (score >= 70) return 'info';
  if (score >= 50) return 'warning';
  return 'default';
}

export function Services() {
  const [services, setServices] = useState<ServiceIntelligence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [sortBy, setSortBy] = useState('name');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [categories, setCategories] = useState<string[]>([]);
  const perPage = 20;
  const tick = useAssessmentChangeTick();

  const fetchServices = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getServices(
        categoryFilter || undefined,
        undefined,
        search || undefined,
        sortBy,
        sortOrder,
        page,
        perPage,
        getActiveAssessmentId() ?? undefined,
      );
      setServices(res.data);
      setTotal(res.pagination.total);
      setTotalPages(res.pagination.total_pages);
    } catch {
      setError('Failed to load services. Please try again.');
    } finally {
      setLoading(false);
    }
  }, [categoryFilter, search, sortBy, sortOrder, page, tick]);

  useEffect(() => {
    fetchServices();
  }, [fetchServices]);

  useEffect(() => {
    getCategories(getActiveAssessmentId() ?? undefined)
      .then((res) => setCategories(res.data))
      .catch(() => {});
  }, [tick]);

  useEffect(() => {
    setPage(1);
  }, [search, categoryFilter, sortBy, sortOrder]);

  const handleSort = (field: string) => {
    if (sortBy === field) {
      setSortOrder((o) => (o === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(field);
      setSortOrder('asc');
    }
  };

  const sortIndicator = (field: string) => {
    if (sortBy !== field) return null;
    return sortOrder === 'asc' ? ' ▲' : ' ▼';
  };

  return (
    <div className="space-y-6">
      <Card
        title="Service Inventory"
        subtitle={`${total} services across ${categories.length} categories`}
      >
        <div className="flex flex-wrap gap-3 mb-6">
          <input
            type="text"
            placeholder="Search services, products, versions..."
            className="input flex-1 min-w-[200px]"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="input w-auto"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
          >
            <option value="">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
        </div>

        {error && (
          <div className="p-4 mb-4 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">
            {error}
            <Button variant="ghost" size="sm" className="ml-3" onClick={fetchServices}>Retry</Button>
          </div>
        )}

        {loading ? (
          <LoadingSpinner size="md" text="Loading services..." />
        ) : services.length === 0 ? (
          <div className="text-center py-12 text-surface-400">
            <p className="text-lg font-medium mb-1">No services found</p>
            <p className="text-sm">Run a port scan with service detection to populate the service inventory.</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-surface-200 dark:border-surface-700">
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('name')}>
                      Service{sortIndicator('name')}
                    </th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase">Host</th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase">Port</th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('normalized_product')}>
                      Product{sortIndicator('normalized_product')}
                    </th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('normalized_version')}>
                      Version{sortIndicator('normalized_version')}
                    </th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('category')}>
                      Category{sortIndicator('category')}
                    </th>
                    <th className="text-left px-3 py-3 text-xs font-medium text-surface-500 uppercase cursor-pointer select-none hover:text-surface-700 dark:hover:text-surface-300" onClick={() => handleSort('confidence')}>
                      Confidence{sortIndicator('confidence')}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-200 dark:divide-surface-700">
                  {services.map((s) => (
                    <tr key={s.id} className="hover:bg-surface-50 dark:hover:bg-surface-800/50">
                      <td className="px-3 py-3">
                        <span className="font-medium text-surface-900 dark:text-surface-100">{s.normalized_name || s.name || '—'}</span>
                        {s.notes && (
                          <span className="block text-xs text-surface-400 mt-0.5" title={s.notes}>{s.notes}</span>
                        )}
                      </td>
                      <td className="px-3 py-3">
                        <span className="font-mono text-xs">{s.host_ip || '—'}</span>
                        {s.host_name && <span className="block text-xs text-surface-400">{s.host_name}</span>}
                      </td>
                      <td className="px-3 py-3">
                        <span className="font-mono text-sm">{s.port_number ? `${s.port_number}/${s.port_protocol || ''}` : '—'}</span>
                      </td>
                      <td className="px-3 py-3 text-surface-600 dark:text-surface-400">
                        {s.normalized_product || s.product || '—'}
                      </td>
                      <td className="px-3 py-3 text-surface-600 dark:text-surface-400 font-mono text-xs">
                        {s.normalized_version || s.version || '—'}
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant={s.category === 'Other' || !s.category ? 'default' : 'info'}>
                          {s.category || 'Uncategorized'}
                        </Badge>
                      </td>
                      <td className="px-3 py-3">
                        <Badge variant={confidenceColor(s.confidence)}>
                          {s.confidence !== null ? `${s.confidence}%` : '—'}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between mt-4 pt-4 border-t border-surface-200 dark:border-surface-700">
              <span className="text-xs text-surface-500">Page {page} of {totalPages} ({total} services)</span>
              <div className="flex gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                >
                  Previous
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
