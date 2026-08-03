import axios, { AxiosError, type AxiosInstance, type AxiosResponse } from 'axios';

import { API_BASE_URL } from '../utils/constants';

const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('auth_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error),
);

apiClient.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error: AxiosError) => {
    if (error.response) {
      const { status } = error.response;
      if (status === 401) {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('refresh_token');
        if (!window.location.pathname.startsWith('/login')) {
          window.location.href = '/login';
        }
      }
    }
    return Promise.reject(error);
  },
);

export function getApiError(error: unknown): string {
  if (error instanceof AxiosError && error.response?.data) {
    const data = error.response.data as {
      error?: { message?: string };
      detail?:
        | string
        | { message?: string; errors?: Record<string, string> }
        | Array<{ msg?: string }>;
    };
    if (data.error?.message) return data.error.message;
    if (typeof data.detail === 'string') return data.detail;
    if (typeof data.detail === 'object' && data.detail !== null && !Array.isArray(data.detail)) {
      if (data.detail.message) return data.detail.message;
    }
    if (Array.isArray(data.detail) && data.detail.length > 0) {
      return data.detail[0].msg || 'An unexpected error occurred';
    }
    return 'An unexpected error occurred';
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'An unexpected error occurred';
}

export default apiClient;
