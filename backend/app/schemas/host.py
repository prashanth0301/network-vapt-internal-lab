import uuid
from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class HostBase(BaseModel):
    ip_address: IPvAnyAddress
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    status: str = "unknown"


class HostCreate(HostBase):
    scan_id: Optional[uuid.UUID] = None


class HostUpdate(BaseModel):
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    status: Optional[str] = None
    is_alive: Optional[bool] = None


class HostResponse(HostBase):
    id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    os_accuracy: Optional[int] = None
    latency: Optional[float] = None
    is_alive: bool = False
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class HostDiscoverRequest(BaseModel):
    target: str = Field(
        default="192.168.56.0/24",
        description="Target IP range in CIDR notation",
        pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$",
    )
    scan_type: str = Field(
        default="ping_sweep",
        pattern="^(ping_sweep|arp_scan|quick_scan)$",
    )


class PortInfo(BaseModel):
    id: uuid.UUID
    port: int
    protocol: str
    state: str
    reason: Optional[str] = None
    created_at: datetime


class ServiceInfo(BaseModel):
    id: uuid.UUID
    port: int
    protocol: str
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    tunnel: Optional[str] = None
    category: Optional[str] = None
    confidence: Optional[int] = None
    normalized_name: Optional[str] = None
    banner: Optional[str] = None


class BannerInfo(BaseModel):
    id: uuid.UUID
    port: int
    protocol: str
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: str


class VulnerabilityInfo(BaseModel):
    id: uuid.UUID
    name: str
    severity: Optional[str] = None
    risk_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    status: Optional[str] = None
    confidence: Optional[int] = None
    cve_ids: Optional[list[str]] = None
    cve_count: Optional[int] = None
    created_at: datetime


class CveInfo(BaseModel):
    id: uuid.UUID
    vulnerability_id: Optional[uuid.UUID] = None
    cve_id: str
    description: Optional[str] = None
    cvss_v3: Optional[float] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    exploit_available: bool = False
    metasploit_module: Optional[str] = None
    epss_score: Optional[float] = None
    kev_status: bool = False
    published_date: Optional[date] = None
    source: Optional[str] = None
    reference_urls: Optional[list[str]] = None


class ExploitInfo(BaseModel):
    id: uuid.UUID
    module_name: Optional[str] = None
    exploit_name: Optional[str] = None
    cve: Optional[str] = None
    rank: Optional[str] = None
    remote_local: Optional[str] = None
    provider: str
    verified: bool = False
    status: Optional[str] = None
    risk_level: Optional[str] = None
    confidence: Optional[int] = None
    session_created: bool = False
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: Optional[float] = None


class EvidenceInfo(BaseModel):
    id: uuid.UUID
    name: str
    severity: Optional[str] = None
    evidence: Optional[str] = None
    plugin_output: Optional[str] = None
    raw_scanner_output: Optional[str] = None
    references: Optional[list[str]] = None
    cve_ids: Optional[list[str]] = None
    created_at: datetime


class ScanHistoryInfo(BaseModel):
    id: uuid.UUID
    name: str
    scan_type: str
    target: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    created_at: datetime


class ReportInfo(BaseModel):
    id: uuid.UUID
    title: str
    report_type: str
    format: str
    file_size: Optional[int] = None
    created_at: datetime


class OSInformation(BaseModel):
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_accuracy: Optional[int] = None
    vendor: Optional[str] = None
    mac_address: Optional[str] = None
    status: str
    is_alive: bool
    latency: Optional[float] = None
    first_seen: datetime
    last_seen: datetime


class HostDetailsSummary(BaseModel):
    ports: int = 0
    open_ports: int = 0
    services: int = 0
    banners: int = 0
    vulnerabilities: int = 0
    cves: int = 0
    exploits: int = 0
    evidence: int = 0
    scans: int = 0
    reports: int = 0


class HostDetailsResponse(BaseModel):
    host: HostResponse
    os_information: OSInformation
    open_ports: list[PortInfo] = []
    services: list[ServiceInfo] = []
    banners: list[BannerInfo] = []
    vulnerabilities: list[VulnerabilityInfo] = []
    cves: list[CveInfo] = []
    exploits: list[ExploitInfo] = []
    evidence: list[EvidenceInfo] = []
    scan_history: list[ScanHistoryInfo] = []
    reports: list[ReportInfo] = []
    summary: HostDetailsSummary
