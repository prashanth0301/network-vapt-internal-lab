import { useCallback, useEffect, useMemo, useState } from 'react';
import { Button } from '../components/ui/Button';
import { Card } from '../components/ui/Card';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { getApiError } from '../services/api';
import {
  getSettings,
  resetSettings,
  saveSettings,
  type SettingItem,
} from '../services/settingsService';

const CATEGORY_LABELS: Record<string, { title: string; subtitle: string }> = {
  network: { title: 'Network Configuration', subtitle: 'Target network and scope settings' },
  scanner: { title: 'Scanner Configuration', subtitle: 'Nmap and vulnerability scanner settings' },
  tools: { title: 'Tool Paths', subtitle: 'Security tool executable locations' },
  custom: { title: 'Custom Settings', subtitle: 'Additional saved settings' },
};

export function Settings() {
  const [settings, setSettings] = useState<SettingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const items = await getSettings();
      setSettings(items);
      setValues(Object.fromEntries(items.map((s) => [s.key, s.value])));
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchSettings(); }, [fetchSettings]);

  const categories = useMemo(() => {
    const seen = new Set<string>();
    return settings.filter((s) => {
      if (seen.has(s.category)) return false;
      seen.add(s.category);
      return true;
    }).map((s) => s.category);
  }, [settings]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const res = await saveSettings(values);
      setSuccessMessage(res.message || 'Settings saved');
      await fetchSettings();
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    setSaving(true);
    setError(null);
    setSuccessMessage(null);
    try {
      const res = await resetSettings();
      setSuccessMessage(res.message || 'Settings reset to defaults');
      await fetchSettings();
    } catch (e) {
      setError(getApiError(e));
    } finally {
      setSaving(false);
    }
  };

  const setValue = (key: string, value: string) => {
    setValues((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div className="space-y-6 max-w-3xl">
      {loading ? (
        <LoadingSpinner size="md" text="Loading settings..." />
      ) : (
        categories.map((category) => (
          <Card key={category} title={CATEGORY_LABELS[category]?.title || category} subtitle={CATEGORY_LABELS[category]?.subtitle}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {settings.filter((s) => s.category === category).map((s) => (
                <div key={s.key}>
                  <label className="block text-sm font-medium text-surface-700 dark:text-surface-300 mb-1">
                    {s.description || s.key}
                  </label>
                  <input
                    type="text"
                    className="input font-mono"
                    value={values[s.key] ?? ''}
                    onChange={(e) => setValue(s.key, e.target.value)}
                  />
                </div>
              ))}
            </div>
          </Card>
        ))
      )}

      {error && (
        <div className="p-3 text-critical bg-critical/10 rounded-lg border border-critical/20 text-sm">{error}</div>
      )}
      {successMessage && (
        <div className="p-3 text-success bg-success/10 rounded-lg border border-success/20 text-sm">{successMessage}</div>
      )}

      <div className="flex justify-end gap-3">
        <Button variant="secondary" onClick={handleReset} disabled={loading || saving}>
          Reset to Defaults
        </Button>
        <Button variant="primary" onClick={handleSave} disabled={loading || saving}>
          {saving ? 'Saving...' : 'Save Settings'}
        </Button>
      </div>
    </div>
  );
}
