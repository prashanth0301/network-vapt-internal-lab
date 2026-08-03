"""Pydantic schemas for the Settings module."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from app.schemas.common import SuccessResponse


class SettingItem(BaseModel):
    key: str
    value: str
    category: str
    description: str
    type: str = "string"
    options: Optional[List[str]] = None
    min: Optional[int] = None
    max: Optional[int] = None
    readonly: bool = False


class SettingsUpdateRequest(BaseModel):
    values: Dict[str, str] = Field(
        default_factory=dict, description="Key/value pairs to save"
    )


class SettingsUpdateResponse(BaseModel):
    updated: int


class ResetResponse(BaseModel):
    reset: bool


class DockerStatus(BaseModel):
    in_container: bool
    mode: str
    container_name: Optional[str] = None


class DatabaseStatus(BaseModel):
    connected: bool
    latency_ms: Optional[float] = None


class VersionInfo(BaseModel):
    name: str
    version: str


class NmapInfo(BaseModel):
    path: str
    version: str


class DiskUsage(BaseModel):
    total_gb: float
    used_gb: float
    free_gb: float
    percent: float


class MemoryInfo(BaseModel):
    total_gb: float
    available_gb: float


class ContainerHealth(BaseModel):
    status: str
    components: Dict[str, str]
    uptime_seconds: Optional[int] = None
    memory: Optional[MemoryInfo] = None
    python_version: Optional[str] = None


class SystemInfoResponse(BaseModel):
    docker: DockerStatus
    database: DatabaseStatus
    backend: VersionInfo
    frontend: VersionInfo
    nmap: NmapInfo
    disk: DiskUsage
    health: ContainerHealth


SettingsListResponse = SuccessResponse[List[SettingItem]]
SettingsSaveResponse = SuccessResponse[SettingsUpdateResponse]
SettingsResetResponse = SuccessResponse[ResetResponse]
SystemInfoListResponse = SuccessResponse[SystemInfoResponse]
