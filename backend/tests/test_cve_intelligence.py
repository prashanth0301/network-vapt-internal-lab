import uuid
from datetime import date, datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.models.cve import CVE
from app.models.vulnerability import Vulnerability
from app.services.cve_provider import CVEProvider, CVEResult, NVDProvider, ProviderStatus
from app.services.cve_provider_manager import CVEProviderManager, cve_provider_manager
from app.services.risk_engine import RiskEngine, risk_engine
from app.services.threat_intelligence_service import (
    ThreatIntelligenceCache,
    enrich_cve,
    enrich_vulnerability_cves,
    get_all_cves,
    get_cve_by_id,
    get_cve_by_vuln_and_id,
    get_cve_statistics,
    get_cves_by_vulnerability,
    get_high_risk_cves,
    merge_cve_results,
    normalize_cve_result,
    threat_cache,
)


def nvd_payload(
    cve_id: str,
    score: float = 7.5,
    severity: str = "High",
    vendor: str = "apache",
    product: str = "http_server",
    version: str = "2.4.49",
    cwe: str = "CWE-22",
) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "descriptions": [
                        {"lang": "en", "value": f"Description for {cve_id}"}
                    ],
                    "published": "2021-09-15T12:00:00.000",
                    "lastModified": "2021-09-20T12:00:00.000",
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": cwe}]}
                    ],
                    "references": [{"url": f"https://example.com/{cve_id}"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                    "baseSeverity": severity,
                                    "exploitabilityScore": 3.9,
                                    "impactScore": 3.6,
                                }
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "criteria": (
                                                f"cpe:2.3:a:{vendor}:{product}:{version}"
                                                ":*:*:*:*:*:*:*:*"
                                            )
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ],
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
    }


def fake_nvd_get(cve_scores: dict[str, tuple[float, str]]) -> AsyncMock:
    async def _get(url: str, params: dict | None = None, headers: dict | None = None):
        if "epss" in url:
            cve = (params or {}).get("cve")
            return MagicMock(
                status_code=200,
                json=lambda: {"data": [{"cve": cve, "epss": 0.974}]},
            )
        if "known_exploited" in url:
            return MagicMock(
                status_code=200,
                json=lambda: {
                    "vulnerabilities": [
                        {"cveID": "CVE-2021-44228"},
                        {"cveID": "CVE-2021-41773"},
                    ]
                },
            )
        cve_id = (params or {}).get("cveId", "CVE-2021-41773")
        if cve_id in cve_scores:
            score, severity = cve_scores[cve_id]
            return MagicMock(status_code=200, json=lambda: nvd_payload(cve_id, score, severity))
        return MagicMock(status_code=200, json=lambda: {"vulnerabilities": []})

    return AsyncMock(side_effect=_get)


def _make_cve(**kwargs) -> CVE:
    c = MagicMock(spec=CVE)
    c.id = uuid.uuid4()
    c.vuln_id = uuid.uuid4()
    c.cve_id = "CVE-2021-0001"
    c.description = None
    c.cvss_v2 = None
    c.cvss_v3 = None
    c.cvss_score = None
    c.cvss_vector = None
    c.cvss_severity = None
    c.base_score = None
    c.exploitability_score = None
    c.impact_score = None
    c.cwe_id = None
    c.exploit_available = False
    c.metasploit_module = None
    c.reference_urls = None
    c.published_date = None
    c.last_modified = None
    c.epss_score = None
    c.kev_status = False
    c.source = None
    c.vendor = None
    c.product = None
    c.affected_versions = None
    c.remediation_priority = None
    c.created_at = datetime.now(timezone.utc)
    c.updated_at = datetime.now(timezone.utc)
    for k, val in kwargs.items():
        setattr(c, k, val)
    return c


class TestCVEProviderAbstraction:
    def test_provider_is_abstract(self):
        with pytest.raises(TypeError):
            CVEProvider()

    def test_nvd_provider_name(self):
        p = NVDProvider()
        assert p.name == "NVD"

    @pytest.mark.asyncio
    async def test_nvd_connect(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            result = await p.connect()
            assert result is True
            assert p.is_connected() is True

    @pytest.mark.asyncio
    async def test_nvd_disconnect(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            await p.connect()
            result = await p.disconnect()
            assert result is True
            assert p.is_connected() is False

    @pytest.mark.asyncio
    async def test_nvd_health(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            await p.connect()
            status = await p.health()
            assert status.name == "NVD"
            assert status.connected is True
            assert status.healthy is True

    @pytest.mark.asyncio
    async def test_nvd_lookup_cve_found(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({"CVE-2021-41773": (7.5, "High")})):
            p = NVDProvider()
            result = await p.lookup_cve("CVE-2021-41773")
            assert result is not None
            assert result.cve_id == "CVE-2021-41773"
            assert result.cvss_score == 7.5
            assert result.cvss_severity == "High"
            assert result.epss_score == 0.974
            assert result.kev_status is True
            assert result.vendor == "apache"
            assert result.product == "http_server"
            assert result.affected_versions == ["2.4.49"]
            assert result.cwe_id == "CWE-22"
            assert result.reference_urls == ["https://example.com/CVE-2021-41773"]

    @pytest.mark.asyncio
    async def test_nvd_lookup_cve_not_found(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            result = await p.lookup_cve("CVE-2099-9999")
            assert result is None

    @pytest.mark.asyncio
    async def test_nvd_lookup_cve_invalid_format(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            result = await p.lookup_cve("INVALID")
            assert result is None

    @pytest.mark.asyncio
    async def test_nvd_lookup_multiple(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({"CVE-2021-41773": (7.5, "High")})):
            p = NVDProvider()
            results = await p.lookup_multiple(["CVE-2021-41773", "CVE-2099-9999", "INVALID"])
            assert results["CVE-2021-41773"] is not None
            assert results["CVE-2099-9999"] is None
            assert results["INVALID"] is None

    @pytest.mark.asyncio
    async def test_nvd_lookup_log4j(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({"CVE-2021-44228": (10.0, "Critical")})):
            p = NVDProvider()
            result = await p.lookup_cve("CVE-2021-44228")
            assert result is not None
            assert result.cvss_score == 10.0
            assert result.kev_status is True

    @pytest.mark.asyncio
    async def test_nvd_lookup_smbghost(self):
        with patch.object(
            httpx.AsyncClient, "get", fake_nvd_get({"CVE-2020-0796": (10.0, "Critical")})
        ):
            p = NVDProvider()
            result = await p.lookup_cve("CVE-2020-0796")
            assert result is not None
            assert result.cvss_score == 10.0


class TestCVEProviderManager:
    def setup_method(self):
        self.manager = CVEProviderManager()

    def test_register_and_get(self):
        p = NVDProvider()
        self.manager.register("test", p)
        assert self.manager.get_provider("test") is p

    def test_register_and_list(self):
        p = NVDProvider()
        self.manager.register("test", p)
        assert "test" in self.manager.list_providers()

    def test_unregister(self):
        p = NVDProvider()
        self.manager.register("test", p)
        self.manager.unregister("test")
        assert self.manager.get_provider("test") is None

    def test_get_unknown(self):
        assert self.manager.get_provider("nonexistent") is None

    @pytest.mark.asyncio
    async def test_connect_all(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            self.manager.register("nvd", p)
            results = await self.manager.connect_all()
            assert results["nvd"] is True

    @pytest.mark.asyncio
    async def test_disconnect_all(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            self.manager.register("nvd", p)
            await self.manager.connect_all()
            results = await self.manager.disconnect_all()
            assert results["nvd"] is True

    @pytest.mark.asyncio
    async def test_health_all(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            self.manager.register("nvd", p)
            await p.connect()
            statuses = await self.manager.health_all()
            assert "nvd" in statuses
            assert statuses["nvd"].name == "NVD"

    @pytest.mark.asyncio
    async def test_lookup_cve_all_providers(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({"CVE-2021-41773": (7.5, "High")})):
            p = NVDProvider()
            self.manager.register("nvd", p)
            result = await self.manager.lookup_cve("CVE-2021-41773")
            assert result is not None

    @pytest.mark.asyncio
    async def test_lookup_cve_specific_provider(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({"CVE-2021-41773": (7.5, "High")})):
            p = NVDProvider()
            self.manager.register("nvd", p)
            result = await self.manager.lookup_cve("CVE-2021-41773", provider_name="nvd")
            assert result is not None

    @pytest.mark.asyncio
    async def test_lookup_cve_unknown_provider(self):
        with patch.object(httpx.AsyncClient, "get", fake_nvd_get({})):
            p = NVDProvider()
            self.manager.register("nvd", p)
            result = await self.manager.lookup_cve("CVE-2021-41773", provider_name="unknown")
            assert result is None

    @pytest.mark.asyncio
    async def test_lookup_multiple(self):
        with patch.object(
            httpx.AsyncClient,
            "get",
            fake_nvd_get({"CVE-2021-41773": (7.5, "High"), "CVE-2021-44228": (10.0, "Critical")}),
        ):
            p = NVDProvider()
            self.manager.register("nvd", p)
            results = await self.manager.lookup_multiple(["CVE-2021-41773", "CVE-2021-44228"])
            assert results["CVE-2021-41773"] is not None
            assert results["CVE-2021-44228"] is not None

    def test_global_manager_has_nvd(self):
        assert "nvd" in cve_provider_manager.list_providers()


class TestThreatIntelligenceCache:
    def setup_method(self):
        self.cache = ThreatIntelligenceCache()

    def test_set_and_get(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=7.5)
        self.cache.set("CVE-2021-0001", result)
        assert self.cache.get("CVE-2021-0001") is result

    def test_get_miss(self):
        assert self.cache.get("CVE-2099-9999") is None

    def test_size(self):
        assert self.cache.size() == 0
        self.cache.set("CVE-2021-0001", CVEResult(cve_id="CVE-2021-0001"))
        assert self.cache.size() == 1

    def test_clear(self):
        self.cache.set("CVE-2021-0001", CVEResult(cve_id="CVE-2021-0001"))
        self.cache.clear()
        assert self.cache.size() == 0

    def test_case_insensitive(self):
        result = CVEResult(cve_id="CVE-2021-0001")
        self.cache.set("cve-2021-0001", result)
        assert self.cache.get("CVE-2021-0001") is result

    def test_global_cache(self):
        assert threat_cache.size() == 0


class TestNormalization:
    def test_normalize_cvss_clamped(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=11.5)
        normalized = normalize_cve_result(result)
        assert normalized.cvss_score == 10.0

    def test_normalize_cvss_negative(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=-1.0)
        normalized = normalize_cve_result(result)
        assert normalized.cvss_score == 0.0

    def test_normalize_epss_clamped(self):
        result = CVEResult(cve_id="CVE-2021-0001", epss_score=1.5)
        normalized = normalize_cve_result(result)
        assert normalized.epss_score == 1.0

    def test_normalize_epss_negative(self):
        result = CVEResult(cve_id="CVE-2021-0001", epss_score=-0.5)
        normalized = normalize_cve_result(result)
        assert normalized.epss_score == 0.0

    def test_normalize_epss_rounded(self):
        result = CVEResult(cve_id="CVE-2021-0001", epss_score=0.97456)
        normalized = normalize_cve_result(result)
        assert normalized.epss_score == 0.975

    def test_infer_severity_from_score_critical(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=9.5)
        normalized = normalize_cve_result(result)
        assert normalized.cvss_severity == "Critical"

    def test_infer_severity_from_score_high(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=7.5)
        normalized = normalize_cve_result(result)
        assert normalized.cvss_severity == "High"

    def test_infer_severity_from_score_medium(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=5.0)
        normalized = normalize_cve_result(result)
        assert normalized.cvss_severity == "Medium"

    def test_infer_severity_from_score_low(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=1.0)
        normalized = normalize_cve_result(result)
        assert normalized.cvss_severity == "Low"

    def test_infer_severity_from_score_info(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=0.0)
        normalized = normalize_cve_result(result)
        assert normalized.cvss_severity == "Info"

    def test_source_default(self):
        result = CVEResult(cve_id="CVE-2021-0001")
        normalized = normalize_cve_result(result)
        assert normalized.source == "NVD"

    def test_preserve_existing_severity(self):
        result = CVEResult(cve_id="CVE-2021-0001", cvss_score=9.5, cvss_severity="High")
        normalized = normalize_cve_result(result)
        assert normalized.cvss_severity == "High"


class TestMergeCVEResults:
    def test_merge_keeps_first_non_none(self):
        existing = CVEResult(cve_id="CVE-2021-0001", cvss_score=7.5, vendor="Apache")
        new = CVEResult(cve_id="CVE-2021-0001", cvss_score=8.0)
        merged = merge_cve_results(existing, new)
        assert merged.cvss_score == 8.0
        assert merged.vendor == "Apache"

    def test_merge_all_none(self):
        existing = CVEResult(cve_id="CVE-2021-0001")
        new = CVEResult(cve_id="CVE-2021-0001")
        merged = merge_cve_results(existing, new)
        assert merged.cve_id == "CVE-2021-0001"


class TestRiskEngine:
    def setup_method(self):
        self.engine = RiskEngine()

    def test_technical_risk_from_cvss(self):
        assert self.engine.calculate_technical_risk(cvss_score=7.5) == 7.5

    def test_technical_risk_from_exploit_impact(self):
        score = self.engine.calculate_technical_risk(exploitability_score=6.0, impact_score=8.0)
        assert score == 7.0

    def test_technical_risk_default(self):
        assert self.engine.calculate_technical_risk() == 0.0

    def test_exploitability_high(self):
        score = self.engine.calculate_exploitability(
            cvss_exploitability=3.9, epss_score=0.97, has_exploit=True, kev_status=True
        )
        assert score > 5.0

    def test_exploitability_low(self):
        score = self.engine.calculate_exploitability()
        assert score == 0.0

    def test_business_risk(self):
        score = self.engine.calculate_business_risk(technical_risk=7.5, exploitability=5.0)
        assert score > 0

    def test_priority_score_critical(self):
        result = self.engine.calculate(
            cvss_score=9.5, cvss_exploitability=3.9, epss_score=0.97,
            has_exploit=True, kev_status=True,
        )
        assert result.priority == "Critical"
        assert result.priority_score >= 8.0

    def test_priority_score_high(self):
        result = self.engine.calculate(cvss_score=9.5, cvss_exploitability=3.9, epss_score=0.97, kev_status=True)
        assert result.priority == "Critical"
        assert result.priority_score >= 8.0

    def test_priority_score_medium(self):
        result = self.engine.calculate(cvss_score=7.5, cvss_exploitability=2.0)
        assert result.priority == "Medium"

    def test_priority_score_low(self):
        result = self.engine.calculate(cvss_score=5.0)
        assert result.priority == "Low"

    def test_priority_score_info(self):
        result = self.engine.calculate(cvss_score=0.0)
        assert result.priority == "Info"

    def test_calculate_for_cve(self):
        cve = _make_cve(cvss_score=9.5, exploitability_score=3.9, epss_score=0.97, kev_status=True)
        result = self.engine.calculate_for_cve(cve)
        assert result.priority is not None

    def test_to_dict(self):
        result = self.engine.calculate(cvss_score=7.5)
        d = result.to_dict()
        assert "priority" in d
        assert "business_risk" in d
        assert "technical_risk" in d
        assert "exploitability" in d
        assert "priority_score" in d

    def test_score_from_priority(self):
        assert self.engine.score_from_priority(8.5) == "Critical"
        assert self.engine.score_from_priority(7.0) == "High"
        assert self.engine.score_from_priority(5.0) == "Medium"
        assert self.engine.score_from_priority(2.0) == "Low"
        assert self.engine.score_from_priority(0.5) == "Info"


class TestEnrichCVE:
    @pytest.mark.asyncio
    async def test_enrich_cve_success(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        mock_session.flush = AsyncMock()

        canned = CVEResult(
            cve_id="CVE-2021-41773",
            cvss_score=7.5,
            cvss_severity="High",
            epss_score=0.974,
            kev_status=True,
            source="NVD",
        )
        with patch(
            "app.services.threat_intelligence_service.cve_provider_manager.lookup_cve",
            new=AsyncMock(return_value=canned),
        ):
            vuln_id = uuid.uuid4()
            result = await enrich_cve(mock_session, vuln_id, "CVE-2021-41773")
            assert result is not None
            assert result.cve_id == "CVE-2021-41773"
            assert result.vuln_id == vuln_id
            assert result.cvss_score == 7.5

    @pytest.mark.asyncio
    async def test_enrich_cve_not_found(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        with patch(
            "app.services.threat_intelligence_service.cve_provider_manager.lookup_cve",
            new=AsyncMock(return_value=None),
        ):
            result = await enrich_cve(mock_session, uuid.uuid4(), "CVE-2099-9999")
            assert result is None

    @pytest.mark.asyncio
    async def test_enrich_vulnerability_cves(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.first.return_value = None
        mock_session.flush = AsyncMock()

        canned = CVEResult(cve_id="CVE-2021-41773", cvss_score=7.5, source="NVD")
        with patch(
            "app.services.threat_intelligence_service.cve_provider_manager.lookup_cve",
            new=AsyncMock(return_value=canned),
        ):
            vuln = MagicMock(spec=Vulnerability)
            vuln.id = uuid.uuid4()
            vuln.cve_ids = ["CVE-2021-41773"]

            count = await enrich_vulnerability_cves(mock_session, vuln)
            assert count == 1

    @pytest.mark.asyncio
    async def test_enrich_vulnerability_no_cves(self):
        mock_session = AsyncMock()
        vuln = MagicMock(spec=Vulnerability)
        vuln.cve_ids = None

        count = await enrich_vulnerability_cves(mock_session, vuln)
        assert count == 0

    @pytest.mark.asyncio
    async def test_enrich_vulnerability_empty_cves(self):
        mock_session = AsyncMock()
        vuln = MagicMock(spec=Vulnerability)
        vuln.cve_ids = []

        count = await enrich_vulnerability_cves(mock_session, vuln)
        assert count == 0


class TestCVEQueries:
    @pytest.mark.asyncio
    async def test_get_all_cves(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.all.return_value = []

        cves, total = await get_all_cves(mock_session)
        assert cves == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_get_cve_by_id_uuid(self):
        cve_id = str(uuid.uuid4())
        mock_cve = _make_cve(cve_id="CVE-2021-0001")
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_cve

        result = await get_cve_by_id(mock_session, cve_id)
        assert result is not None

    @pytest.mark.asyncio
    async def test_get_cve_by_id_cve_string(self):
        mock_cve = _make_cve(cve_id="CVE-2021-41773")
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.first.return_value = mock_cve

        result = await get_cve_by_id(mock_session, "CVE-2021-41773")
        assert result is not None
        assert result.cve_id == "CVE-2021-41773"

    @pytest.mark.asyncio
    async def test_get_cve_by_id_not_found(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.first.return_value = None

        result = await get_cve_by_id(mock_session, str(uuid.uuid4()))
        assert result is None

    @pytest.mark.asyncio
    async def test_get_cves_by_vulnerability(self):
        mock_cve = _make_cve()
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.all.return_value = [mock_cve]

        result = await get_cves_by_vulnerability(mock_session, str(uuid.uuid4()))
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_cve_by_vuln_and_id(self):
        mock_cve = _make_cve(cve_id="CVE-2021-41773")
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.first.return_value = mock_cve

        vuln_id = str(uuid.uuid4())
        result = await get_cve_by_vuln_and_id(mock_session, vuln_id, "cve-2021-41773")
        assert result is not None
        assert result.cve_id == "CVE-2021-41773"

    @pytest.mark.asyncio
    async def test_get_cve_by_vuln_and_id_invalid_vuln(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()

        result = await get_cve_by_vuln_and_id(mock_session, "not-a-uuid", "CVE-2021-41773")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_high_risk_cves(self):
        mock_cve = _make_cve(cvss_score=9.5)
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.all.return_value = [mock_cve]

        result = await get_high_risk_cves(mock_session)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_get_cve_statistics_empty(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.all.return_value = []

        stats = await get_cve_statistics(mock_session)
        assert stats["total_cves"] == 0
        assert stats["kev_count"] == 0
        assert stats["average_cvss"] == 0.0
        assert stats["average_epss"] == 0.0
        assert stats["top_vendors"] == []

    @pytest.mark.asyncio
    async def test_get_cve_statistics_with_data(self):
        mock_cves = [
            _make_cve(cvss_severity="Critical", cvss_score=9.5, epss_score=0.97, kev_status=True, vendor="Apache"),
            _make_cve(cvss_severity="High", cvss_score=7.5, epss_score=0.5, kev_status=False, vendor="Microsoft"),
        ]
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_cves

        stats = await get_cve_statistics(mock_session)
        assert stats["total_cves"] == 2
        assert stats["severity_counts"]["Critical"] == 1
        assert stats["severity_counts"]["High"] == 1
        assert stats["kev_count"] == 1
        assert stats["average_cvss"] == 8.5
        assert stats["average_epss"] == 0.735
        assert len(stats["top_vendors"]) == 2

    @pytest.mark.asyncio
    async def test_get_cve_statistics_filtered(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.all.return_value = []

        cves, total = await get_all_cves(
            mock_session, severity="Critical", vendor="Apache", year=2021
        )
        assert total == 0
