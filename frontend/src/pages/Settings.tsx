import { AxiosError } from 'axios';
import {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { Badge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { Modal } from '../components/ui/Modal';
import { ProgressBar } from '../components/ui/ProgressBar';
import { StatCard } from '../components/ui/StatCard';
import { AuthContext } from '../context/AuthContext';
import { ThemeContext } from '../context/ThemeContext';
import { useToast } from '../hooks/useToast';
import { getApiError } from '../services/api';
import {
  fetchLogoUrl,
  getSettings,
  getSystemInfo,
  removeLogo,
  resetSettings,
  saveSettings,
  uploadLogo,
} from '../services/settingsService';
import type { SettingItem, SystemInfo } from '../types/settings';

const TABS = [
  { id: 'general', label: 'General', icon: '🏷️' },
  { id: 'scanner', label: 'Scanner', icon: '📡' },
  { id: 'reporting', label: 'Reporting', icon: '📊' },
  { id: 'security', label: 'Security', icon: '🔒' },
  { id: 'system', label: 'System', icon: '🖥️' },
] as const;

type TabId = (typeof TABS)[number]['id'];

const inputClass = 'input w-full';

function FieldError({ message }: { message?: string | null }) {
  if (!message) return null;
  return <p className="mt-1 text-xs text-critical">{message}</p>;
}

function Toggle({
  checked,
  disabled,
  onChange,
}: {
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${
        checked ? 'bg-low' : 'bg-surface-300 dark:bg-surface-600'
      } disabled:cursor-not-allowed disabled:opacity-40`}
    >
      <span
        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
          checked ? 'translate-x-[18px]' : 'translate-x-[3px]'
        }`}
      />
    </button>
  );
}

function formatUptime(seconds: number | null): string {
  if (seconds === null) return 'Unknown';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function settingValue(
  items: SettingItem[],
  key: string,
): SettingItem | undefined {
  return items.find((i) => i.key === key);
}

export function Settings() {
  const { hasPermission } = useContext(AuthContext);
  const { setTheme } = useContext(ThemeContext);
  const { addToast } = useToast();

  const canEdit = hasPermission('manage:settings');
  const [activeTab, setActiveTab] = useState<TabId>('general');

  const [items, setItems] = useState<SettingItem[]>([]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [original, setOriginal] = useState<Record<string, string>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
  const [resetting, setResetting] = useState(false);

  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [sysLoading, setSysLoading] = useState(false);

  const [logoUrl, setLogoUrl] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getSettings();
      const list = res.data || [];
      setItems(list);
      const map = Object.fromEntries(list.map((s) => [s.key, s.value]));
      setValues(map);
      setOriginal(map);
      setFieldErrors({});

      const themeSetting = settingValue(list, 'general.theme');
      if (themeSetting) {
        if (themeSetting.value === 'light' || themeSetting.value === 'dark') {
          setTheme(themeSetting.value);
        } else if (themeSetting.value === 'system') {
          setTheme(
            window.matchMedia('(prefers-color-scheme: dark)').matches
              ? 'dark'
              : 'light',
          );
        }
      }
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  }, [setTheme]);

  const refreshLogo = useCallback(async () => {
    const url = await fetchLogoUrl();
    setLogoUrl((prev) => {
      if (prev) URL.revokeObjectURL(prev);
      return url;
    });
  }, []);

  const loadSystemInfo = useCallback(async () => {
    setSysLoading(true);
    try {
      const res = await getSystemInfo();
      setSystemInfo(res.data);
    } catch (e) {
      addToast({ type: 'error', title: 'Failed to load system info', message: getApiError(e) });
    } finally {
      setSysLoading(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchSettings();
    return () => {
      setLogoUrl((prev) => {
        if (prev) URL.revokeObjectURL(prev);
        return null;
      });
    };
  }, [fetchSettings]);

  useEffect(() => {
    if (activeTab === 'system') loadSystemInfo();
  }, [activeTab, loadSystemInfo]);

  const byCategory = useMemo(() => {
    const groups = new Map<string, SettingItem[]>();
    for (const item of items) {
      const list = groups.get(item.category) ?? [];
      list.push(item);
      groups.set(item.category, list);
    }
    return groups;
  }, [items]);

  const activeItems = byCategory.get(activeTab) ?? [];

  const dirtyKeys = useMemo(() => {
    return activeItems
      .filter((i) => !i.readonly && values[i.key] !== original[i.key])
      .map((i) => i.key);
  }, [activeItems, values, original]);

  const setValue = (key: string, value: string) => {
    setValues((prev) => ({ ...prev, [key]: value }));
    setFieldErrors((prev) => {
      if (!(key in prev)) return prev;
      const next = { ...prev };
      delete next[key];
      return next;
    });
  };

  const handleSaveTab = async () => {
    if (dirtyKeys.length === 0) {
      addToast({ type: 'info', title: 'No changes to save' });
      return;
    }
    setSaving(true);
    setError(null);
    const payload = Object.fromEntries(
      dirtyKeys.map((k) => [k, values[k] ?? '']),
    );
    try {
      const res = await saveSettings(payload);
      addToast({ type: 'success', title: res.message || 'Settings saved' });
      await fetchSettings();
      await refreshLogo();
    } catch (e) {
      const errors = extractFieldErrors(e);
      if (errors) {
        setFieldErrors(errors);
      }
      addToast({ type: 'error', title: 'Failed to save settings', message: getApiError(e) });
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    setResetting(true);
    try {
      const res = await resetSettings();
      addToast({ type: 'success', title: res.message || 'Settings reset to defaults' });
      setResetOpen(false);
      await fetchSettings();
      await refreshLogo();
    } catch (e) {
      addToast({ type: 'error', title: 'Failed to reset settings', message: getApiError(e) });
    } finally {
      setResetting(false);
    }
  };

  const handleLogoUpload = async (file: File | undefined) => {
    if (!file) return;
    setUploading(true);
    try {
      const res = await uploadLogo(file);
      addToast({ type: 'success', title: res.message || 'Company logo uploaded' });
      await fetchSettings();
      await refreshLogo();
    } catch (e) {
      addToast({ type: 'error', title: 'Logo upload failed', message: getApiError(e) });
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleLogoRemove = async () => {
    setUploading(true);
    try {
      const res = await removeLogo();
      addToast({ type: 'success', title: res.message || 'Company logo removed' });
      await fetchSettings();
      await refreshLogo();
    } catch (e) {
      addToast({ type: 'error', title: 'Failed to remove logo', message: getApiError(e) });
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card title="Settings" subtitle="Platform-wide configuration">
        <div className="flex flex-wrap gap-2 border-b border-surface-200 dark:border-surface-700 pb-4">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-primary-500 text-white'
                  : 'text-surface-600 dark:text-surface-300 hover:bg-surface-100 dark:hover:bg-surface-700'
              }`}
            >
              <span className="mr-1.5">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>

        {!canEdit && (
          <div className="mt-4 p-3 rounded-lg bg-info/10 text-info text-sm">
            You have read-only access to settings. Only administrators can modify them.
          </div>
        )}

        {error && (
          <div className="mt-4 p-3 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">
            {error}
          </div>
        )}

        {loading ? (
          <LoadingSpinner size="md" text="Loading settings..." />
        ) : activeTab === 'system' ? (
          <SystemTab
            info={systemInfo}
            loading={sysLoading}
            onRefresh={loadSystemInfo}
          />
        ) : (
          <SettingsForm
            items={activeItems}
            values={values}
            fieldErrors={fieldErrors}
            canEdit={canEdit}
            onChange={setValue}
            category={activeTab}
            logoUrl={logoUrl}
            uploading={uploading}
            onLogoUpload={handleLogoUpload}
            onLogoRemove={handleLogoRemove}
            fileInputRef={fileInputRef}
          />
        )}

        {canEdit && activeTab !== 'system' && (
          <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-surface-200 dark:border-surface-700">
            <Button
              variant="secondary"
              onClick={() => setResetOpen(true)}
              disabled={saving}
            >
              Reset to Defaults
            </Button>
            <Button
              variant="primary"
              onClick={handleSaveTab}
              loading={saving}
              disabled={dirtyKeys.length === 0}
            >
              {saving ? 'Saving...' : `Save ${TABS.find((t) => t.id === activeTab)?.label} Settings`}
            </Button>
          </div>
        )}
      </Card>

      <Modal
        open={resetOpen}
        onClose={() => setResetOpen(false)}
        title="Reset Settings"
        size="sm"
        footer={
          <>
            <Button variant="secondary" onClick={() => setResetOpen(false)} disabled={resetting}>
              Cancel
            </Button>
            <Button variant="danger" loading={resetting} onClick={handleReset}>
              Reset to Defaults
            </Button>
          </>
        }
      >
        <p className="text-sm text-surface-700 dark:text-surface-300">
          This will restore all settings to their default values, including the company
          logo. This action cannot be undone.
        </p>
      </Modal>
    </div>
  );
}

function extractFieldErrors(e: unknown): Record<string, string> | null {
  if (e instanceof AxiosError && e.response?.data) {
    const data = e.response.data as {
      detail?: { errors?: Record<string, string> };
    };
    if (data.detail?.errors) return data.detail.errors;
  }
  return null;
}

function SettingsForm({
  items,
  values,
  fieldErrors,
  canEdit,
  onChange,
  category,
  logoUrl,
  uploading,
  onLogoUpload,
  onLogoRemove,
  fileInputRef,
}: {
  items: SettingItem[];
  values: Record<string, string>;
  fieldErrors: Record<string, string>;
  canEdit: boolean;
  onChange: (key: string, value: string) => void;
  category: string;
  logoUrl: string | null;
  uploading: boolean;
  onLogoUpload: (file: File | undefined) => void;
  onLogoRemove: () => void;
  fileInputRef: { current: HTMLInputElement | null };
}) {
  if (items.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-surface-400 text-sm">No settings in this section.</p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
      {items.map((item) => {
        const disabled = !canEdit || item.readonly;
        return (
          <div key={item.key}>
            <div className="flex items-center justify-between">
              <label className="block text-sm font-medium text-surface-700 dark:text-surface-300">
                {item.description}
              </label>
              {item.readonly && (
                <Badge variant="info">Auto-detected</Badge>
              )}
            </div>
            {category === 'general' && item.key === 'general.company_logo' ? (
              <LogoField
                logoUrl={logoUrl}
                uploading={uploading}
                canEdit={canEdit}
                onUpload={onLogoUpload}
                onRemove={onLogoRemove}
                fileInputRef={fileInputRef}
              />
            ) : item.type === 'boolean' ? (
              <div className="mt-2">
                <Toggle
                  checked={values[item.key] === 'true'}
                  disabled={disabled}
                  onChange={(checked) =>
                    onChange(item.key, checked ? 'true' : 'false')
                  }
                />
              </div>
            ) : item.type === 'enum' ? (
              <>
                <select
                  className={`${inputClass} mt-2`}
                  value={values[item.key] ?? ''}
                  disabled={disabled}
                  onChange={(e) => onChange(item.key, e.target.value)}
                >
                  {(item.options ?? []).map((opt) => (
                    <option key={opt} value={opt}>
                      {opt}
                    </option>
                  ))}
                </select>
                <FieldError message={fieldErrors[item.key]} />
              </>
            ) : item.type === 'integer' ? (
              <>
                <input
                  type="number"
                  className={`${inputClass} mt-2`}
                  value={values[item.key] ?? ''}
                  min={item.min ?? undefined}
                  max={item.max ?? undefined}
                  disabled={disabled}
                  onChange={(e) => onChange(item.key, e.target.value)}
                />
                <p className="mt-1 text-xs text-surface-400">
                  {item.min !== null && item.min !== undefined && item.max !== null && item.max !== undefined
                    ? `Allowed range: ${item.min} - ${item.max}`
                    : ''}
                </p>
                <FieldError message={fieldErrors[item.key]} />
              </>
            ) : (
              <>
                <input
                  type="text"
                  className={`${inputClass} mt-2`}
                  value={values[item.key] ?? ''}
                  disabled={disabled}
                  onChange={(e) => onChange(item.key, e.target.value)}
                />
                <FieldError message={fieldErrors[item.key]} />
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}

function LogoField({
  logoUrl,
  uploading,
  canEdit,
  onUpload,
  onRemove,
  fileInputRef,
}: {
  logoUrl: string | null;
  uploading: boolean;
  canEdit: boolean;
  onUpload: (file: File | undefined) => void;
  onRemove: () => void;
  fileInputRef: { current: HTMLInputElement | null };
}) {
  return (
    <div className="mt-2">
      <div className="flex items-center gap-4">
        {logoUrl ? (
          <img
            src={logoUrl}
            alt="Company logo"
            className="h-14 w-14 object-contain rounded-lg border border-surface-200 dark:border-surface-700 bg-white p-1"
          />
        ) : (
          <div className="h-14 w-14 rounded-lg border border-dashed border-surface-300 dark:border-surface-600 flex items-center justify-center text-xs text-surface-400">
            No logo
          </div>
        )}
        <div className="flex flex-col gap-1.5">
          {canEdit && (
            <>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/png,image/jpeg,image/webp,image/svg+xml"
                className="hidden"
                onChange={(e) => onUpload(e.target.files?.[0])}
              />
              <Button
                size="sm"
                variant="secondary"
                loading={uploading}
                disabled={uploading}
                onClick={() => fileInputRef.current?.click()}
              >
                {uploading ? 'Uploading...' : 'Upload Logo'}
              </Button>
              {logoUrl && (
                <Button size="sm" variant="ghost" disabled={uploading} onClick={onRemove}>
                  Remove
                </Button>
              )}
            </>
          )}
        </div>
      </div>
      <p className="mt-2 text-xs text-surface-400">
        PNG, JPEG, WebP or SVG up to 2 MB. Used in the header and generated reports.
      </p>
    </div>
  );
}

function SystemTab({
  info,
  loading,
  onRefresh,
}: {
  info: SystemInfo | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  if (loading && !info) {
    return <LoadingSpinner size="md" text="Collecting system information..." />;
  }
  if (!info) {
    return (
      <div className="py-12 text-center space-y-4">
        <p className="text-surface-400 text-sm">System information unavailable.</p>
        <Button size="sm" variant="secondary" onClick={onRefresh}>
          Retry
        </Button>
      </div>
    );
  }

  const dbOk = info.database.connected;
  const diskColor =
    info.disk.percent >= 90 ? 'danger' : info.disk.percent >= 75 ? 'warning' : 'success';

  return (
    <div className="space-y-6 mt-4">
      <div className="flex justify-end">
        <Button size="sm" variant="secondary" onClick={onRefresh} disabled={loading}>
          Refresh
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        <StatCard
          title="Docker Status"
          icon={<span>🐳</span>}
          value={info.docker.mode === 'docker' ? 'Running in container' : 'Bare metal'}
          color={info.docker.in_container ? 'info' : 'warning'}
          subtitle={info.docker.container_name ?? 'Not containerized'}
        />
        <StatCard
          title="Database Status"
          icon={<span>🗄️</span>}
          value={dbOk ? 'Connected' : 'Disconnected'}
          color={dbOk ? 'success' : 'danger'}
          subtitle={dbOk && info.database.latency_ms !== null ? `${info.database.latency_ms} ms latency` : undefined}
        />
        <StatCard
          title="Backend Version"
          icon={<span>⚙️</span>}
          value={info.backend.version}
          subtitle={info.backend.name}
        />
        <StatCard
          title="Frontend Version"
          icon={<span>🖥️</span>}
          value={info.frontend.version}
          subtitle={info.frontend.name}
        />
        <StatCard
          title="Nmap Version"
          icon={<span>📡</span>}
          value={info.nmap.version === 'Not installed' ? 'Not installed' : info.nmap.version.replace('Nmap version ', '')}
          color={info.nmap.version === 'Not installed' ? 'danger' : 'primary'}
          subtitle={info.nmap.path}
        />
        <StatCard
          title="Container Health"
          icon={<span>💚</span>}
          value={info.health.status}
          color={info.health.status === 'healthy' ? 'success' : 'warning'}
          subtitle={
            info.health.uptime_seconds !== null
              ? `Uptime: ${formatUptime(info.health.uptime_seconds)}`
              : undefined
          }
        />
      </div>

      <Card title="Disk Usage" subtitle="Filesystem utilization">
        <ProgressBar
          value={info.disk.percent}
          color={diskColor}
          size="md"
          showLabel
        />
        <p className="text-xs text-surface-400 mt-2">
          {info.disk.used_gb} GB used of {info.disk.total_gb} GB · {info.disk.free_gb} GB free
        </p>
      </Card>

      <Card title="Health Details">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <HealthRow label="Application" status={info.health.components['app'] ?? 'unknown'} />
          <HealthRow label="Database" status={info.health.components['database'] ?? 'unknown'} />
          <HealthRow label="Disk" status={info.health.components['disk'] ?? 'unknown'} />
          {info.health.memory && (
            <div>
              <span className="text-surface-400">Memory: </span>
              <span className="text-surface-700 dark:text-surface-300">
                {info.health.memory.available_gb} GB available / {info.health.memory.total_gb} GB
              </span>
            </div>
          )}
      {info.health.python_version && (
        <div>
          <span className="text-surface-400">Python: </span>
          <span className="font-mono text-xs">{info.health.python_version}</span>
        </div>
      )}
      </div>
      </Card>
    </div>
  );
}

function HealthRow({ label, status }: { label: string; status: string }) {
  const ok = status === 'ok';
  return (
    <div className="flex items-center justify-between">
      <span className="text-surface-400">{label}:</span>
      <Badge variant={ok ? 'success' : 'danger'}>{status}</Badge>
    </div>
  );
}
