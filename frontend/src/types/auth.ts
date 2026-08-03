export interface User {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  role: string;
  status: string;
  last_login: string | null;
  is_active: boolean;
  permissions?: string[];
  created_at: string;
  updated_at: string;
}

export interface UserMe extends User {
  permissions: string[];
}

export interface LoginRequest {
  username: string;
  password: string;
  remember_me?: boolean;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

export interface UserListResponse {
  items: User[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

export interface UserStatusPayload {
  status: 'active' | 'inactive' | 'disabled';
}

export interface UserRolePayload {
  role: 'administrator' | 'security_analyst' | 'viewer';
}

export interface PasswordResetPayload {
  password: string;
}

export interface AuditLog {
  id: string;
  user_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  timestamp: string;
}
