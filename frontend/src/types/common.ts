export interface ApiResponse<T> {
  status?: 'success' | 'error';
  data: T;
  message?: string;
  timestamp?: string;
}

export interface PaginatedResponse<T> {
  status?: 'success' | 'error';
  data: T[];
  pagination: {
    page: number;
    per_page: number;
    total: number;
    total_pages: number;
  };
  timestamp?: string;
}

export interface ErrorResponse {
  status: 'error';
  error: {
    error_code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  timestamp: string;
}

export interface BreadcrumbItem {
  label: string;
  path?: string;
}

export interface NavItem {
  label: string;
  path: string;
  icon: string;
  badge?: number;
}
