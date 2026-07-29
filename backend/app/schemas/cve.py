import uuid
from datetime import date, datetime
from typing import Optional

from pydantic import BaseModel


class CVEResponse(BaseModel):
    id: uuid.UUID
    vuln_id: Optional[uuid.UUID] = None
    cve_id: str
    description: Optional[str] = None
    cvss_v2: Optional[float] = None
    cvss_v3: Optional[float] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_severity: Optional[str] = None
    base_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None
    cwe_id: Optional[str] = None
    exploit_available: bool = False
    metasploit_module: Optional[str] = None
    reference_urls: Optional[list[str]] = None
    published_date: Optional[date] = None
    last_modified: Optional[datetime] = None
    epss_score: Optional[float] = None
    kev_status: bool = False
    source: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    affected_versions: Optional[list[str]] = None
    remediation_priority: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CVEStatisticsResponse(BaseModel):
    total_cves: int
    severity_counts: dict[str, int]
    kev_count: int
    average_cvss: float
    average_epss: float
    top_vendors: list[dict]
