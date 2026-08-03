import re
import shutil
from datetime import datetime, timezone
from typing import Optional

from loguru import logger

from app.services.nmap_service import run_scan
from app.services.scanner.base import (
    ScanResult,
    ScannerStatus,
    VulnerabilityFinding,
    VulnerabilityScanner,
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_VULNERS_LINE_RE = re.compile(r"(CVE-\d{4}-\d{4,})\s+(\d+(?:\.\d+)?)")
_CVSS_SCORE_RE = re.compile(r"(?:CVSS(?:\s+Score)?[:\s]?|score[:\s])\s*(\d+(?:\.\d+)?)", re.IGNORECASE)
_VULNERABLE_TOKEN_RE = re.compile(r"(?<!not )VULNERABLE", re.IGNORECASE)


def _parse_cves(text: str) -> list[str]:
    cves = _CVE_RE.findall(text or "")
    return list(dict.fromkeys(c.upper() for c in cves))


def _parse_cvss(text: str) -> Optional[float]:
    match = _CVSS_SCORE_RE.search(text or "")
    if match:
        try:
            return round(min(10.0, max(0.0, float(match.group(1)))), 1)
        except (ValueError, TypeError):
            return None
    return None


class NmapVulnScanner(VulnerabilityScanner):
    """Nmap NSE-based vulnerability scanner using the vuln and vulners script
    categories. Runs `nmap -sV --script vuln,vulners` against the discovered
    open ports and converts the NSE script results into VulnerabilityFindings.
    """

    def __init__(self):
        super().__init__(name="nmap")
        self._connected = shutil.which("nmap") is not None

    async def connect(self) -> bool:
        self._connected = shutil.which("nmap") is not None
        if not self._connected:
            logger.error("Nmap executable not found - NSE vulnerability scanning unavailable")
        return self._connected

    async def disconnect(self) -> bool:
        self._connected = False
        return True

    async def scan(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_profile: Optional[str] = None,
    ) -> str:
        scan_id = f"nmap-nse-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{hash(target) % 10000:04d}"
        logger.info("Nmap NSE scan {sid} started for {target}", sid=scan_id, target=target)
        return scan_id

    async def cancel(self, scan_id: str) -> bool:
        return True

    async def get_status(self, scan_id: str) -> ScannerStatus:
        return ScannerStatus.COMPLETED

    async def fetch_results(self, scan_id: str) -> ScanResult:
        return ScanResult(
            scan_id=scan_id,
            status=ScannerStatus.COMPLETED,
            findings=[],
            started_at=datetime.now(timezone.utc),
        )

    async def run_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_profile: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ScanResult:
        start = datetime.now(timezone.utc)
        scan_id = await self.scan(target, ports, scan_profile)

        if not ports:
            return ScanResult(
                scan_id=scan_id,
                status=ScannerStatus.COMPLETED,
                findings=[],
                error="No open ports to scan for vulnerabilities",
                started_at=start,
                completed_at=datetime.now(timezone.utc),
                duration_seconds=0.0,
            )

        nmap_result = await run_scan(
            scan_type="vuln_scan",
            target=target,
            ports=ports,
            timeout=timeout or 300,
        )

        if nmap_result.error:
            logger.warning(
                "Nmap NSE vuln scan failed for {target}: {error}",
                target=target,
                error=nmap_result.error,
            )
            return ScanResult(
                scan_id=scan_id,
                status=ScannerStatus.FAILED,
                findings=[],
                error=nmap_result.error,
                started_at=start,
                completed_at=nmap_result.completed_at,
                duration_seconds=nmap_result.duration_seconds,
            )

        findings = self._parse_findings(nmap_result.raw_output or "", target)

        logger.info(
            "Nmap NSE vuln scan completed for {target}: {count} findings in {duration:.1f}s",
            target=target,
            count=len(findings),
            duration=nmap_result.duration_seconds or 0.0,
        )

        return ScanResult(
            scan_id=scan_id,
            status=ScannerStatus.COMPLETED,
            findings=findings,
            started_at=start,
            completed_at=nmap_result.completed_at,
            duration_seconds=nmap_result.duration_seconds,
        )

    def _parse_findings(self, raw_xml: str, host_ip: str) -> list[VulnerabilityFinding]:
        import xml.etree.ElementTree as ET

        findings: list[VulnerabilityFinding] = []
        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError as e:
            logger.error("Failed to parse Nmap NSE XML: {error}", error=str(e))
            return findings

        for host_elem in root.findall("host"):
            address_elem = host_elem.find("address")
            if address_elem is None:
                continue
            ip = address_elem.get("addr") or host_ip

            for port_elem in host_elem.findall("./ports/port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                port_id = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                service_elem = port_elem.find("service")
                product = service_elem.get("product") if service_elem is not None else None
                version = service_elem.get("version") if service_elem is not None else None
                service_name = service_elem.get("name") if service_elem is not None else None

                for script_elem in port_elem.findall("script"):
                    self._append_script_findings(
                        findings,
                        script_elem,
                        host_ip=ip,
                        port=port_id,
                        protocol=protocol,
                        service_name=service_name,
                        product=product,
                        version=version,
                    )

            for script_elem in host_elem.findall("./hostscript/script"):
                self._append_script_findings(
                    findings,
                    script_elem,
                    host_ip=ip,
                    port=None,
                    protocol=None,
                    service_name=None,
                    product=None,
                    version=None,
                )

        return findings

    @staticmethod
    def _append_script_findings(
        findings: list[VulnerabilityFinding],
        script_elem,
        host_ip: str,
        port: Optional[int],
        protocol: Optional[str],
        service_name: Optional[str],
        product: Optional[str],
        version: Optional[str],
    ) -> None:
        script_id = script_elem.get("id", "unknown")
        if script_id == "banner":
            return
        output = script_elem.get("output", "") or ""
        if not output.strip():
            return

        cves = _parse_cves(output)
        score = _parse_cvss(output)
        vulnerable = bool(_VULNERABLE_TOKEN_RE.search(output)) or bool(cves)

        if not vulnerable:
            return

        if script_id == "vulners":
            for cve, cvss_str in _VULNERS_LINE_RE.findall(output):
                try:
                    cve_score = round(min(10.0, max(0.0, float(cvss_str))), 1)
                except (ValueError, TypeError):
                    cve_score = score
                findings.append(
                    VulnerabilityFinding(
                        scanner_id=script_id,
                        title=f"Vulnerable service ({service_name or 'unknown'}): {cve.upper()}",
                        description=(
                            f"Service {service_name or 'unknown'}"
                            + (f" {product or ''}" if product else "")
                            + (f" {version or ''}" if version else "")
                            + f" matches a known vulnerability {cve.upper()} "
                            f"per the vulners NSE database."
                        ),
                        severity=NmapVulnScanner._severity_from_score(cve_score),
                        cvss_score=cve_score,
                        affected_product=product,
                        affected_version=version,
                        evidence=output[:2000],
                        recommendation="Upgrade the affected service to a patched version.",
                        cve_ids=[cve.upper()],
                        plugin_output=output[:4000],
                        raw_data=output,
                        port=port,
                        protocol=protocol,
                        host_ip=host_ip,
                    )
                )
            return

        findings.append(
            VulnerabilityFinding(
                scanner_id=script_id,
                title=f"{script_id}: {cves[0] if cves else 'vulnerable service detected'}",
                description=output.splitlines()[0][:500] if output else script_id,
                severity=NmapVulnScanner._severity_from_score(score),
                cvss_score=score,
                affected_product=product,
                affected_version=version,
                evidence=output[:2000],
                recommendation="Review the NSE script output and apply the vendor patch.",
                cve_ids=cves or None,
                plugin_output=output[:4000],
                raw_data=output,
                port=port,
                protocol=protocol,
                host_ip=host_ip,
            )
        )

    @staticmethod
    def _severity_from_score(score: Optional[float]) -> str:
        if score is None:
            return "Info"
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        if score >= 0.1:
            return "Low"
        return "Info"

    def normalize_finding(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        finding.severity = self.normalize_severity(finding.severity)
        finding.cvss_score = self.normalize_cvss_score(finding.cvss_score)
        if not finding.cve_ids and finding.raw_data:
            finding.cve_ids = _parse_cves(finding.raw_data) or None
        return finding
