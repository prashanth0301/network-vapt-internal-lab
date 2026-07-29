from datetime import datetime, timezone
from typing import Optional

from loguru import logger

from app.services.scanner.base import (
    ScanResult,
    ScannerStatus,
    VulnerabilityFinding,
    VulnerabilityScanner,
)


class OpenVASScanner(VulnerabilityScanner):
    def __init__(self):
        super().__init__(name="OpenVAS")
        self._host = ""
        self._port = 0
        self._username = ""
        self._password = ""

    def configure(
        self,
        host: str = "127.0.0.1",
        port: int = 9390,
        username: str = "admin",
        password: str = "admin",
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        logger.info(
            "OpenVAS configured: {host}:{port}", host=self._host, port=self._port
        )

    async def connect(self) -> bool:
        if not self._host:
            logger.error("OpenVAS cannot connect: host not configured")
            self._connected = False
            return False
        logger.info("OpenVAS connecting to {host}:{port}", host=self._host, port=self._port)
        self._connected = True
        return True

    async def disconnect(self) -> bool:
        logger.info("OpenVAS disconnecting from {host}:{port}", host=self._host, port=self._port)
        self._connected = False
        return True

    async def scan(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_profile: Optional[str] = None,
    ) -> str:
        scan_id = f"openvas-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{hash(target) % 10000:04d}"
        logger.info(
            "OpenVAS scan {sid} started for {target}",
            sid=scan_id,
            target=target,
        )
        return scan_id

    async def cancel(self, scan_id: str) -> bool:
        logger.info("OpenVAS cancelling scan {sid}", sid=scan_id)
        return True

    async def run_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_profile: Optional[str] = None,
    ) -> ScanResult:
        scan_id = f"openvas-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{hash(target) % 10000:04d}"
        logger.info(
            "OpenVAS scan {sid} started for {target}",
            sid=scan_id,
            target=target,
        )
        return ScanResult(
            scan_id=scan_id,
            status=ScannerStatus.COMPLETED,
            findings=[],
            error="OpenVAS is not available - scanner adapter not connected",
            started_at=datetime.now(timezone.utc),
        )

    async def get_status(self, scan_id: str) -> ScannerStatus:
        return ScannerStatus.FAILED

    async def fetch_results(self, scan_id: str) -> ScanResult:
        return ScanResult(
            scan_id=scan_id,
            status=ScannerStatus.FAILED,
            error="OpenVAS is not available - scanner adapter not connected",
            started_at=datetime.now(timezone.utc),
        )

    def normalize_finding(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        finding.severity = self.normalize_severity(finding.severity)
        finding.cvss_score = self.normalize_cvss_score(finding.cvss_score)
        if not finding.severity or finding.severity == "Info":
            if finding.cvss_score is not None:
                finding.severity = self.severity_from_cvss(finding.cvss_score)
        return finding
