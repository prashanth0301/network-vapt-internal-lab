export type SettingType = 'string' | 'boolean' | 'integer' | 'enum';

export interface SettingItem {
  key: string;
  value: string;
  category: string;
  description: string;
  type: SettingType;
  options?: string[] | null;
  min?: number | null;
  max?: number | null;
  readonly?: boolean;
}

export interface DockerStatus {
  in_container: boolean;
  mode: string;
  container_name: string | null;
}

export interface DatabaseStatus {
  connected: boolean;
  latency_ms: number | null;
}

export interface VersionInfo {
  name: string;
  version: string;
}

export interface NmapInfo {
  path: string;
  version: string;
}

export interface DiskUsage {
  total_gb: number;
  used_gb: number;
  free_gb: number;
  percent: number;
}

export interface MemoryInfo {
  total_gb: number;
  available_gb: number;
}

export interface ContainerHealth {
  status: string;
  components: Record<string, string>;
  uptime_seconds: number | null;
  memory: MemoryInfo | null;
  python_version: string | null;
}

export interface SystemInfo {
  docker: DockerStatus;
  database: DatabaseStatus;
  backend: VersionInfo;
  frontend: VersionInfo;
  nmap: NmapInfo;
  disk: DiskUsage;
  health: ContainerHealth;
}
