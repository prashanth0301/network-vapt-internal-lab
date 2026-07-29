from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Optional


@dataclass
class CVEResult:
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
    reference_urls: Optional[list[str]] = None
    published_date: Optional[date] = None
    last_modified: Optional[datetime] = None
    epss_score: Optional[float] = None
    kev_status: bool = False
    source: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    affected_versions: Optional[list[str]] = None


@dataclass
class ProviderStatus:
    name: str
    connected: bool
    healthy: bool
    error: Optional[str] = None


class CVEProvider(ABC):
    def __init__(self, name: str = "unknown"):
        self.name = name
        self._connected = False

    @abstractmethod
    async def connect(self) -> bool:
        pass

    @abstractmethod
    async def lookup_cve(self, cve_id: str) -> Optional[CVEResult]:
        pass

    @abstractmethod
    async def lookup_multiple(
        self, cve_ids: list[str]
    ) -> dict[str, Optional[CVEResult]]:
        pass

    @abstractmethod
    async def disconnect(self) -> bool:
        pass

    @abstractmethod
    async def health(self) -> ProviderStatus:
        pass

    def is_connected(self) -> bool:
        return self._connected
