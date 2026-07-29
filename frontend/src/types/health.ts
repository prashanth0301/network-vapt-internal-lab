export interface HealthResponse {
  status: string;
  version: string;
  app_name: string;
  database: string;
  uptime_seconds: number;
  services: Record<string, string>;
  timestamp: string;
}
