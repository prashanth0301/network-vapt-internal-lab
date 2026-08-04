import type { ApiResponse } from '../types/common';
import type {
  LoginRequest,
  PasswordResetPayload,
  TokenResponse,
  User,
  UserListResponse,
  UserRolePayload,
  UserStatusPayload,
} from '../types/auth';
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

export interface UserListParams {
  search?: string;
  status?: string;
  role?: string;
  page?: number;
  per_page?: number;
}

export async function getUsersPaged(
  params: UserListParams = {},
): Promise<ApiResponse<UserListResponse>> {
  const query = new URLSearchParams();
  if (params.search) query.set('search', params.search);
  if (params.status) query.set('status', params.status);
  if (params.role) query.set('role', params.role);
  if (params.page) query.set('page', String(params.page));
  if (params.per_page) query.set('per_page', String(params.per_page));
  const response = await apiClient.get<ApiResponse<UserListResponse>>(`/users?${query.toString()}`);
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

export async function updateUserStatus(
  id: string,
  payload: UserStatusPayload,
): Promise<ApiResponse<User>> {
  const response = await apiClient.put<ApiResponse<User>>(`/users/${id}/status`, payload);
  return response.data;
}

export async function updateUserRole(
  id: string,
  payload: UserRolePayload,
): Promise<ApiResponse<User>> {
  const response = await apiClient.put<ApiResponse<User>>(`/users/${id}/role`, payload);
  return response.data;
}

export async function resetUserPassword(
  id: string,
  payload: PasswordResetPayload,
): Promise<ApiResponse<Record<string, unknown>>> {
  const response = await apiClient.put<ApiResponse<Record<string, unknown>>>(`/users/${id}/password`, payload);
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
