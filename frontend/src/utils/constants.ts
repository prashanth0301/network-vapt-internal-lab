export const APP_NAME = 'Network VAPT Platform';
export const APP_VERSION = '1.0.0';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export const ROUTES = {
  DASHBOARD: '/',
  HOSTS: '/hosts',
  SCANNING: '/scanning',
  WORKSPACE: '/workspace',
  VULNERABILITIES: '/vulnerabilities',
  EXPLOITATION: '/exploitation',
  PACKETS: '/packets',
  REPORTS: '/reports',
  SETTINGS: '/settings',
} as const;

export const SEVERITY_COLORS = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
} as const;

export const SCAN_STATUS_COLORS = {
  pending: 'bg-surface-400',
  running: 'bg-primary-500',
  completed: 'bg-low',
  failed: 'bg-critical',
} as const;

export const THEME_STORAGE_KEY = 'vapt-theme';
