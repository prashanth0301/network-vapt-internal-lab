import re
import time
from datetime import date, datetime, timezone
from typing import Optional

import httpx
from loguru import logger

from app.core.config import settings
from app.services.cve_provider.base import CVEProvider, CVEResult, ProviderStatus

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_KEV_CACHE_TTL_SECONDS = 6 * 3600


def is_valid_cve_id(text: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", text, re.IGNORECASE))


class NVDProvider(CVEProvider):
    def __init__(self):
        super().__init__(name="NVD")
        self._timeout = 25.0
        self._kev_cache: dict[str, object] = {}

    async def connect(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    NVD_API_URL,
                    params={"cveId": "CVE-2021-44228"},
                    headers=self._headers(),
                )
                self._connected = response.status_code == 200
        except httpx.HTTPError as e:
            logger.warning("NVD provider unreachable: {error}", error=str(e))
            self._connected = False
        return self._connected

    async def disconnect(self) -> bool:
        self._connected = False
        return True

    async def health(self) -> ProviderStatus:
        return ProviderStatus(
            name=self.name,
            connected=self._connected,
            healthy=self._connected,
            error=None if self._connected else "NVD API unreachable",
        )

    def _headers(self) -> dict[str, str]:
        if settings.NVD_API_KEY:
            return {"apiKey": settings.NVD_API_KEY}
        return {}

    async def lookup_cve(self, cve_id: str) -> Optional[CVEResult]:
        if not is_valid_cve_id(cve_id):
            logger.warning("Invalid CVE ID format: {cve}", cve=cve_id)
            return None
        normalized = cve_id.upper()
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(
                    NVD_API_URL,
                    params={"cveId": normalized},
                    headers=self._headers(),
                )
                if response.status_code != 200:
                    if response.status_code == 404:
                        logger.info("CVE {cve} not found in NVD", cve=normalized)
                        return None
                    logger.warning(
                        "NVD lookup failed for {cve}: HTTP {status}",
                        cve=normalized,
                        status=response.status_code,
                    )
                    return None
                payload = response.json()
        except httpx.HTTPError as e:
            logger.warning("NVD lookup failed for {cve}: {error}", cve=normalized, error=str(e))
            return None

        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            return None
        raw = vulns[0].get("cve") or {}
        result = self._parse_nvd_record(normalized, raw)
        if result is None:
            return None

        await self._apply_epss(result)
        await self._apply_kev(result)
        self._connected = True
        return result

    def _parse_nvd_record(self, cve_id: str, raw: dict) -> Optional[CVEResult]:
        description = None
        for desc in raw.get("descriptions") or []:
            if desc.get("lang") == "en":
                description = desc.get("value")
                break
        if description is None and raw.get("descriptions"):
            description = raw["descriptions"][0].get("value")

        published = None
        if raw.get("published"):
            try:
                published = date.fromisoformat(raw["published"][:10])
            except ValueError:
                published = None

        last_modified = None
        if raw.get("lastModified"):
            try:
                last_modified = datetime.fromisoformat(
                    raw["lastModified"].replace("Z", "+00:00")
                )
            except ValueError:
                last_modified = None

        cwe_id = None
        for weakness in raw.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                if desc.get("value", "").startswith("CWE-"):
                    cwe_id = desc["value"]
                    break
            if cwe_id:
                break

        reference_urls = [
            ref.get("url") for ref in (raw.get("references") or []) if ref.get("url")
        ] or None

        cvss_v3 = cvss_v2 = None
        cvss_score = None
        cvss_vector = None
        cvss_severity = None
        base_score = None
        exploitability_score = None
        impact_score = None

        metrics = raw.get("metrics") or {}
        metric31 = (metrics.get("cvssMetricV31") or [None])[0]
        metric30 = (metrics.get("cvssMetricV30") or [None])[0]
        metric2 = (metrics.get("cvssMetricV2") or [None])[0]
        cvss_data = None
        if metric31:
            cvss_data = metric31.get("cvssData")
        elif metric30:
            cvss_data = metric30.get("cvssData")
        elif metric2:
            cvss_data = metric2.get("cvssData")

        if cvss_data:
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            cvss_severity = cvss_data.get("baseSeverity")
            base_score = cvss_data.get("baseScore")
            exploitability_score = cvss_data.get("exploitabilityScore")
            impact_score = cvss_data.get("impactScore")
            if metric31 or metric30:
                cvss_v3 = cvss_score
            else:
                cvss_v2 = cvss_score
        elif metric2:
            cvss_v2 = metric2.get("cvssData", {}).get("baseScore")
            cvss_score = cvss_v2
            base_score = cvss_v2
            exploitability_score = metric2.get("exploitabilityScore")
            impact_score = metric2.get("impactScore")
            cvss_severity = metric2.get("baseSeverity")

        vendor, product, affected_versions = self._parse_cpes(raw)

        return CVEResult(
            cve_id=cve_id,
            description=description,
            cvss_v2=cvss_v2,
            cvss_v3=cvss_v3,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_severity=cvss_severity,
            base_score=base_score,
            exploitability_score=exploitability_score,
            impact_score=impact_score,
            cwe_id=cwe_id,
            reference_urls=reference_urls,
            published_date=published,
            last_modified=last_modified,
            epss_score=None,
            kev_status=False,
            source="NVD",
            vendor=vendor,
            product=product,
            affected_versions=affected_versions,
        )

    @staticmethod
    def _parse_cpes(raw: dict) -> tuple[Optional[str], Optional[str], Optional[list[str]]]:
        vendor = None
        product = None
        versions: set[str] = set()
        configs = raw.get("configurations") or []
        if isinstance(configs, dict):
            configs = [configs]
        for config in configs:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] in ("2.3", "2.2"):
                        if vendor is None:
                            vendor = parts[3] or None
                        if product is None:
                            product = parts[4] or None
                        version = parts[5]
                        if version and version not in ("*", "-"):
                            versions.add(version)
        affected = sorted(versions)[:50] if versions else None
        return vendor, product, affected

    async def _apply_epss(self, result: CVEResult) -> None:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(
                    EPSS_API_URL,
                    params={"cve": result.cve_id},
                )
                if response.status_code == 200:
                    data = response.json()
                    for item in data.get("data") or []:
                        if item.get("cve") == result.cve_id:
                            result.epss_score = item.get("epss")
                            break
        except httpx.HTTPError as e:
            logger.debug("EPSS lookup failed for {cve}: {error}", cve=result.cve_id, error=str(e))

    async def _apply_kev(self, result: CVEResult) -> None:
        now = time.monotonic()
        if "items" not in self._kev_cache or now - self._kev_cache.get("ts", 0) > _KEV_CACHE_TTL_SECONDS:
            try:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    response = await client.get(KEV_FEED_URL)
                    if response.status_code == 200:
                        payload = response.json()
                        self._kev_cache = {
                            "ts": now,
                            "items": {item.get("cveID") for item in payload.get("vulnerabilities") or []},
                        }
                    else:
                        logger.debug("KEV feed request failed: HTTP {status}", status=response.status_code)
            except httpx.HTTPError as e:
                logger.debug("KEV feed unavailable: {error}", error=str(e))
        if "items" in self._kev_cache:
            result.kev_status = result.cve_id in self._kev_cache["items"]

    async def lookup_multiple(
        self, cve_ids: list[str]
    ) -> dict[str, Optional[CVEResult]]:
        results: dict[str, Optional[CVEResult]] = {}
        for cve_id in cve_ids:
            results[cve_id] = await self.lookup_cve(cve_id)
        return results
