import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class ScannerStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class VulnerabilityFinding:
    scanner_id: str
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_product: Optional[str] = None
    affected_version: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    cve_ids: Optional[list[str]] = None
    plugin_output: Optional[str] = None
    raw_data: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    host_ip: Optional[str] = None


@dataclass
class ScanResult:
    scan_id: str
    status: ScannerStatus
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    error: Optional[str] = None
    duration_seconds: Optional[float] = None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None


class VulnerabilityScanner(ABC):
    def __init__(self, name: str = "unknown"):
        self.name = name

    @abstractmethod
    async def run_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_profile: Optional[str] = None,
    ) -> ScanResult:
        pass

    @abstractmethod
    async def get_status(self, scan_id: str) -> ScannerStatus:
        pass

    @abstractmethod
    async def fetch_results(self, scan_id: str) -> ScanResult:
        pass

    def normalize_severity(self, severity: Optional[str]) -> str:
        if not severity:
            return "Info"
        severity_lower = severity.strip().lower()
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "none": "Info",
            "log": "Info",
            "debug": "Info",
        }
        return mapping.get(severity_lower, severity.strip())

    def normalize_cvss_score(self, score: Optional[float]) -> Optional[float]:
        if score is None:
            return None
        return round(max(0.0, min(10.0, float(score))), 1)

    def severity_from_cvss(self, cvss_score: Optional[float]) -> str:
        if cvss_score is None:
            return "Info"
        if cvss_score >= 9.0:
            return "Critical"
        if cvss_score >= 7.0:
            return "High"
        if cvss_score >= 4.0:
            return "Medium"
        if cvss_score >= 0.1:
            return "Low"
        return "Info"
