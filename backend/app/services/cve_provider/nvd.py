import re
from datetime import date, datetime, timezone
from typing import Optional

from loguru import logger

from app.services.cve_provider.base import CVEProvider, CVEResult, ProviderStatus

MOCK_CVE_DB: dict[str, dict] = {
    "CVE-2021-41773": {
        "cve_id": "CVE-2021-41773",
        "description": "A flaw was found in Apache HTTP Server 2.4.49. A path traversal attack could result in directory listing or remote code execution.",
        "cvss_v3": 7.5,
        "cvss_score": 7.5,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_severity": "High",
        "base_score": 7.5,
        "exploitability_score": 3.9,
        "impact_score": 3.6,
        "cwe_id": "CWE-22",
        "published_date": date(2021, 10, 5),
        "last_modified": datetime(2022, 6, 15, tzinfo=timezone.utc),
        "epss_score": 0.974,
        "kev_status": True,
        "source": "NVD",
        "vendor": "Apache",
        "product": "HTTP Server",
        "affected_versions": ["2.4.49"],
        "reference_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            "https://httpd.apache.org/security/vulnerabilities_24.html",
        ],
    },
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding 2.12.2, 2.12.3, 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "cvss_v3": 10.0,
        "cvss_score": 10.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_severity": "Critical",
        "base_score": 10.0,
        "exploitability_score": 3.9,
        "impact_score": 6.0,
        "cwe_id": "CWE-502",
        "published_date": date(2021, 12, 10),
        "last_modified": datetime(2023, 8, 1, tzinfo=timezone.utc),
        "epss_score": 0.975,
        "kev_status": True,
        "source": "NVD",
        "vendor": "Apache",
        "product": "Log4j",
        "affected_versions": ["2.0-beta9 - 2.15.0"],
        "reference_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log4j/2.x/security.html",
        ],
    },
    "CVE-2020-0796": {
        "cve_id": "CVE-2020-0796",
        "description": "A remote code execution vulnerability exists in the way that Microsoft Server Message Block 3.1.1 (SMBv3) handles certain requests.",
        "cvss_v3": 10.0,
        "cvss_score": 10.0,
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_severity": "Critical",
        "base_score": 10.0,
        "exploitability_score": 3.9,
        "impact_score": 6.0,
        "cwe_id": "CWE-122",
        "published_date": date(2020, 3, 12),
        "last_modified": datetime(2021, 4, 10, tzinfo=timezone.utc),
        "epss_score": 0.969,
        "kev_status": True,
        "source": "NVD",
        "vendor": "Microsoft",
        "product": "Windows SMBv3",
        "affected_versions": ["Windows 10 v1903+", "Windows Server 1903+"],
        "reference_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796",
        ],
    },
}


def is_valid_cve_id(text: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", text, re.IGNORECASE))


class NVDProvider(CVEProvider):
    def __init__(self, use_mock: bool = True):
        super().__init__(name="NVD")
        self._use_mock = use_mock

    async def connect(self) -> bool:
        logger.info("NVD provider connected (mock={mock})", mock=self._use_mock)
        self._connected = True
        return True

    async def disconnect(self) -> bool:
        logger.info("NVD provider disconnected")
        self._connected = False
        return True

    async def health(self) -> ProviderStatus:
        return ProviderStatus(
            name=self.name,
            connected=self._connected,
            healthy=self._connected,
        )

    async def lookup_cve(self, cve_id: str) -> Optional[CVEResult]:
        if not is_valid_cve_id(cve_id):
            logger.warning("Invalid CVE ID format: {cve}", cve=cve_id)
            return None
        normalized_cve = cve_id.upper()
        if not self._use_mock:
            logger.info("Live NVD lookup for {cve} (not implemented)", cve=normalized_cve)
            return None
        raw = MOCK_CVE_DB.get(normalized_cve)
        if not raw:
            logger.info("CVE {cve} not found in mock database", cve=normalized_cve)
            return None
        logger.info("Mock lookup for {cve} successful", cve=normalized_cve)
        return CVEResult(**raw)

    async def lookup_multiple(
        self, cve_ids: list[str]
    ) -> dict[str, Optional[CVEResult]]:
        results: dict[str, Optional[CVEResult]] = {}
        for cve_id in cve_ids:
            results[cve_id] = await self.lookup_cve(cve_id)
        return results
