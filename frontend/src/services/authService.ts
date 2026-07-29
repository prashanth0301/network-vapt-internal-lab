import type { ApiResponse } from '../types/common';
import type { AuditLog, LoginRequest, TokenResponse, User } from '../types/auth';
import apiClient from './api';

export async function login(payload: LoginRequest): Promise<ApiResponse<TokenResponse>> {
  const response = await apiClient.post<ApiResponse<TokenResponse>>('/auth/login', payload);
  return response.data;
}

export async function logout(): Promise<ApiResponse<Record<string, unknown>>> {
  const response = await apiClient.post<ApiResponse<Record<string, unknown>>>('/auth/logout');
  return response.data;
}

export async function refreshToken(refresh_token: string): Promise<ApiResponse<TokenResponse>> {
  const response = await apiClient.post<ApiResponse<TokenResponse>>('/auth/refresh', { refresh_token });
  return response.data;
}

export async function getMe(): Promise<ApiResponse<User>> {
  const response = await apiClient.get<ApiResponse<User>>('/auth/me');
  return response.data;
}

export async function getUsers(): Promise<ApiResponse<User[]>> {
  const response = await apiClient.get<ApiResponse<User[]>>('/users');
  return response.data;
}

export async function getUserById(id: string): Promise<ApiResponse<User>> {
  const response = await apiClient.get<ApiResponse<User>>(`/users/${id}`);
  return response.data;
}

export async function createUser(payload: {
  username: string;
  email: string;
  password: string;
  full_name?: string;
  role?: string;
}): Promise<ApiResponse<User>> {
  const response = await apiClient.post<ApiResponse<User>>('/users', payload);
  return response.data;
}

export async function updateUser(
  id: string,
  payload: {
    email?: string;
    full_name?: string;
    role?: string;
    status?: string;
    password?: string;
  },
): Promise<ApiResponse<User>> {
  const response = await apiClient.put<ApiResponse<User>>(`/users/${id}`, payload);
  return response.data;
}

export async function deleteUser(id: string): Promise<ApiResponse<Record<string, unknown>>> {
  const response = await apiClient.delete<ApiResponse<Record<string, unknown>>>(`/users/${id}`);
  return response.data;
}

export async function getRoles(): Promise<ApiResponse<{ roles: string[]; permissions: Record<string, string[]> }>> {
  const response = await apiClient.get<ApiResponse<{ roles: string[]; permissions: Record<string, string[]> }>>('/roles');
  return response.data;
}

export async function getPermissions(): Promise<ApiResponse<{ role: string; permissions: string[]; all_permissions: Record<string, string[]> }>> {
  const response = await apiClient.get<ApiResponse<{ role: string; permissions: string[]; all_permissions: Record<string, string[]> }>>('/permissions');
  return response.data;
}

export async function getAuditLogs(): Promise<ApiResponse<AuditLog[]>> {
  const response = await apiClient.get<ApiResponse<AuditLog[]>>('/audit-logs');
  return response.data;
}
