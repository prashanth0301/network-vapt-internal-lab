import uuid
from datetime import date, datetime, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.vulnerability import Vulnerability
from app.services.cve_provider import CVEResult
from app.services.cve_provider_manager import cve_provider_manager


class ThreatIntelligenceCache:
    def __init__(self):
        self._cache: dict[str, CVEResult] = {}

    def get(self, cve_id: str) -> Optional[CVEResult]:
        return self._cache.get(cve_id.upper())

    def set(self, cve_id: str, result: CVEResult) -> None:
        self._cache[cve_id.upper()] = result

    def clear(self) -> None:
        self._cache.clear()

    def size(self) -> int:
        return len(self._cache)


threat_cache = ThreatIntelligenceCache()


def normalize_cve_result(result: CVEResult) -> CVEResult:
    if result.cvss_score is not None:
        result.cvss_score = round(max(0.0, min(10.0, float(result.cvss_score))), 1)
    if result.cvss_v3 is not None:
        result.cvss_v3 = round(max(0.0, min(10.0, float(result.cvss_v3))), 1)
    if result.cvss_v2 is not None:
        result.cvss_v2 = round(max(0.0, min(10.0, float(result.cvss_v2))), 1)
    if result.epss_score is not None:
        result.epss_score = round(max(0.0, min(1.0, float(result.epss_score))), 3)
    if result.cvss_severity is None and result.cvss_score is not None:
        score = result.cvss_score
        if score >= 9.0:
            result.cvss_severity = "Critical"
        elif score >= 7.0:
            result.cvss_severity = "High"
        elif score >= 4.0:
            result.cvss_severity = "Medium"
        elif score >= 0.1:
            result.cvss_severity = "Low"
        else:
            result.cvss_severity = "Info"
    if result.source is None:
        result.source = "NVD"
    return result


def merge_cve_results(existing: CVEResult, new: CVEResult) -> CVEResult:
    merged = CVEResult(cve_id=existing.cve_id)
    for field in [
        "description", "cvss_v2", "cvss_v3", "cvss_score", "cvss_vector",
        "cvss_severity", "base_score", "exploitability_score", "impact_score",
        "cwe_id", "reference_urls", "published_date", "last_modified",
        "epss_score", "kev_status", "source", "vendor", "product",
        "affected_versions",
    ]:
        existing_val = getattr(existing, field)
        new_val = getattr(new, field)
        setattr(merged, field, new_val if new_val is not None else existing_val)
    return merged


async def enrich_cve(
    session: AsyncSession,
    vuln_id: uuid.UUID,
    cve_id: str,
) -> Optional[CVE]:
    normalized_cve = cve_id.upper().strip()

    cached = threat_cache.get(normalized_cve)
    if cached:
        logger.debug("Cache hit for {cve}", cve=normalized_cve)
        result = cached
    else:
        result = await cve_provider_manager.lookup_cve(normalized_cve)
        if result is None:
            logger.warning("No intelligence found for {cve}", cve=normalized_cve)
            return None
        result = normalize_cve_result(result)
        threat_cache.set(normalized_cve, result)

    cve_record = CVE(
        vuln_id=vuln_id,
        cve_id=normalized_cve,
        description=result.description,
        cvss_v2=result.cvss_v2,
        cvss_v3=result.cvss_v3,
        cvss_score=result.cvss_score,
        cvss_vector=result.cvss_vector,
        cvss_severity=result.cvss_severity,
        base_score=result.base_score,
        exploitability_score=result.exploitability_score,
        impact_score=result.impact_score,
        cwe_id=result.cwe_id,
        reference_urls=result.reference_urls,
        published_date=result.published_date,
        last_modified=result.last_modified,
        epss_score=result.epss_score,
        kev_status=result.kev_status,
        source=result.source,
        vendor=result.vendor,
        product=result.product,
        affected_versions=result.affected_versions,
    )
    session.add(cve_record)
    await session.flush()
    logger.info("Enriched CVE {cve} for vulnerability {vuln}", cve=normalized_cve, vuln=vuln_id)
    return cve_record


async def enrich_vulnerability_cves(
    session: AsyncSession,
    vuln: Vulnerability,
) -> int:
    if not vuln.cve_ids:
        return 0
    enriched_count = 0
    for cve_id in vuln.cve_ids:
        existing = await session.execute(
            select(CVE).where(
                CVE.cve_id == cve_id.upper(),
                CVE.vuln_id == vuln.id,
            )
        )
        if existing.scalar_one_or_none() is not None:
            continue
        result = await enrich_cve(session, vuln.id, cve_id)
        if result is not None:
            enriched_count += 1
    return enriched_count


async def get_all_cves(
    session: AsyncSession,
    page: int = 1,
    per_page: int = 20,
    severity: Optional[str] = None,
    vendor: Optional[str] = None,
    product: Optional[str] = None,
    year: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "cvss_score",
    sort_order: str = "desc",
    kev_only: bool = False,
    assessment_id: Optional[str] = None,
) -> tuple[list[CVE], int]:
    query = select(CVE)
    count_query = select(CVE.id).select_from(CVE)

    if assessment_id:
        try:
            aid = uuid.UUID(assessment_id)
        except ValueError:
            return [], 0
        query = query.join(Vulnerability, CVE.vuln_id == Vulnerability.id)
        query = query.where(Vulnerability.scan_id == aid)
        count_query = (
            count_query.join(Vulnerability, CVE.vuln_id == Vulnerability.id)
            .where(Vulnerability.scan_id == aid)
        )

    if severity:
        query = query.where(CVE.cvss_severity == severity)
        count_query = count_query.where(CVE.cvss_severity == severity)
    if vendor:
        query = query.where(CVE.vendor.ilike(f"%{vendor}%"))
        count_query = count_query.where(CVE.vendor.ilike(f"%{vendor}%"))
    if product:
        query = query.where(CVE.product.ilike(f"%{product}%"))
        count_query = count_query.where(CVE.product.ilike(f"%{product}%"))
    if year:
        query = query.where(CVE.cve_id.like(f"CVE-{year}-%"))
        count_query = count_query.where(CVE.cve_id.like(f"CVE-{year}-%"))
    if search:
        query = query.where(
            CVE.description.ilike(f"%{search}%")
            | CVE.cve_id.ilike(f"%{search}%")
        )
        count_query = count_query.where(
            CVE.description.ilike(f"%{search}%")
            | CVE.cve_id.ilike(f"%{search}%")
        )
    if kev_only:
        query = query.where(CVE.kev_status == True)
        count_query = count_query.where(CVE.kev_status == True)

    total_result = await session.execute(count_query)
    total = len(total_result.fetchall())

    sortable = {
        "cvss_score": CVE.cvss_score,
        "cvss_severity": CVE.cvss_severity,
        "published_date": CVE.published_date,
        "epss_score": CVE.epss_score,
        "cve_id": CVE.cve_id,
        "vendor": CVE.vendor,
        "remediation_priority": CVE.remediation_priority,
    }
    sort_col = sortable.get(sort_by, CVE.cvss_score)
    if sort_order == "desc":
        sort_col = sort_col.desc()
    else:
        sort_col = sort_col.asc()

    query = query.order_by(sort_col).offset((page - 1) * per_page).limit(per_page)
    result = await session.execute(query)
    cves = list(result.scalars().all())
    return cves, total


async def get_cve_by_id(
    session: AsyncSession, cve_id: str
) -> Optional[CVE]:
    try:
        uid = uuid.UUID(cve_id)
    except (ValueError, AttributeError):
        uid = None
    if uid:
        result = await session.execute(
            select(CVE).where(CVE.id == uid)
        )
    else:
        result = await session.execute(
            select(CVE).where(CVE.cve_id == cve_id.upper())
        )
    return result.scalar_one_or_none()


async def get_cves_by_vulnerability(
    session: AsyncSession, vuln_id: str
) -> list[CVE]:
    result = await session.execute(
        select(CVE).where(CVE.vuln_id == uuid.UUID(vuln_id))
        .order_by(CVE.cvss_score.desc().nullslast())
    )
    return list(result.scalars().all())


async def get_cve_statistics(
    session: AsyncSession,
    assessment_id: Optional[str] = None,
) -> dict:
    query = select(CVE)
    if assessment_id:
        try:
            aid = uuid.UUID(assessment_id)
        except ValueError:
            return {
                "total_cves": 0,
                "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
                "kev_count": 0,
                "average_cvss": 0.0,
                "average_epss": 0.0,
                "top_vendors": [],
            }
        query = query.join(Vulnerability, CVE.vuln_id == Vulnerability.id)
        query = query.where(Vulnerability.scan_id == aid)
    result = await session.execute(query)
    all_cves = list(result.scalars().all())

    total = len(all_cves)
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    kev_count = 0
    total_cvss = 0.0
    cvss_count = 0
    total_epss = 0.0
    epss_count = 0
    vendors: dict[str, int] = {}

    for cve in all_cves:
        sev = cve.cvss_severity or "Info"
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts[sev] = 1
        if cve.kev_status:
            kev_count += 1
        if cve.cvss_score is not None:
            total_cvss += cve.cvss_score
            cvss_count += 1
        if cve.epss_score is not None:
            total_epss += cve.epss_score
            epss_count += 1
        if cve.vendor:
            vendors[cve.vendor] = vendors.get(cve.vendor, 0) + 1

    top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_cves": total,
        "severity_counts": severity_counts,
        "kev_count": kev_count,
        "average_cvss": round(total_cvss / cvss_count, 1) if cvss_count > 0 else 0.0,
        "average_epss": round(total_epss / epss_count, 3) if epss_count > 0 else 0.0,
        "top_vendors": [{"vendor": v, "count": c} for v, c in top_vendors],
    }


async def get_high_risk_cves(
    session: AsyncSession,
    limit: int = 20,
    assessment_id: Optional[str] = None,
) -> list[CVE]:
    query = select(CVE).where(CVE.cvss_score >= 7.0)
    if assessment_id:
        try:
            aid = uuid.UUID(assessment_id)
        except ValueError:
            return []
        query = query.join(Vulnerability, CVE.vuln_id == Vulnerability.id)
        query = query.where(Vulnerability.scan_id == aid)
    result = await session.execute(
        query.order_by(CVE.cvss_score.desc().nullslast()).limit(limit)
    )
    return list(result.scalars().all())
