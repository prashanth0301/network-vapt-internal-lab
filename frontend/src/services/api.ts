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
      }
    }
    return Promise.reject(error);
  },
);

export function getApiError(error: unknown): string {
  if (error instanceof AxiosError && error.response?.data) {
    const data = error.response.data as { error?: { message?: string } };
    return data.error?.message || 'An unexpected error occurred';
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'An unexpected error occurred';
}

export default apiClient;
