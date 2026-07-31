from typing import Optional

from fastapi import APIRouter, Depends, Query
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.schemas.common import PaginatedResponse, SuccessResponse
from app.schemas.cve import CVEResponse, CVEStatisticsResponse

router = APIRouter(prefix="/cves", tags=["CVEs"])


@router.get("", response_model=PaginatedResponse[CVEResponse])
async def list_cves(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    vendor: Optional[str] = Query(None, description="Filter by vendor"),
    product: Optional[str] = Query(None, description="Filter by product"),
    year: Optional[int] = Query(None, description="Filter by CVE year"),
    search: Optional[str] = Query(None, description="Search in CVE ID and description"),
    kev_only: bool = Query(False, description="Show only KEV CVEs"),
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    sort_by: str = Query("cvss_score", description="Sort field"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    from app.services.threat_intelligence_service import get_all_cves

    cves, total = await get_all_cves(
        session=db,
        page=page,
        per_page=per_page,
        severity=severity,
        vendor=vendor,
        product=product,
        year=year,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        kev_only=kev_only,
        assessment_id=assessment_id,
    )
    items = [_cve_to_response(c) for c in cves]
    total_pages = max(1, (total + per_page - 1) // per_page)
    return PaginatedResponse(
        data=items,
        pagination={"page": page, "per_page": per_page, "total": total, "total_pages": total_pages},
    )


@router.get("/search", response_model=SuccessResponse[list[CVEResponse]])
async def search_cves(
    q: str = Query(..., min_length=1, description="Search query"),
    db: AsyncSession = Depends(get_db),
):
    from app.services.threat_intelligence_service import get_all_cves

    cves, _ = await get_all_cves(session=db, search=q, per_page=50)
    items = [_cve_to_response(c) for c in cves]
    return SuccessResponse(data=items, message=f"Found {len(items)} CVEs")


@router.get("/high-risk", response_model=SuccessResponse[list[CVEResponse]])
async def list_high_risk_cves(
    limit: int = Query(20, ge=1, le=100),
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    db: AsyncSession = Depends(get_db),
):
    from app.services.threat_intelligence_service import get_high_risk_cves

    cves = await get_high_risk_cves(db, limit=limit, assessment_id=assessment_id)
    items = [_cve_to_response(c) for c in cves]
    return SuccessResponse(data=items, message=f"Found {len(items)} high-risk CVEs")


@router.get("/statistics", response_model=SuccessResponse[CVEStatisticsResponse])
async def cve_statistics(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    db: AsyncSession = Depends(get_db),
):
    from app.services.threat_intelligence_service import get_cve_statistics

    stats = await get_cve_statistics(db, assessment_id)
    return SuccessResponse(data=stats, message="CVE statistics retrieved")


@router.get("/by-vulnerability/{vuln_id}", response_model=SuccessResponse[list[CVEResponse]])
async def list_cves_by_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
):
    from app.services.threat_intelligence_service import get_cves_by_vulnerability

    cves = await get_cves_by_vulnerability(db, vuln_id)
    items = [_cve_to_response(c) for c in cves]
    return SuccessResponse(data=items, message=f"Found {len(items)} CVEs for vulnerability")


@router.get("/{cve_id}", response_model=SuccessResponse[CVEResponse])
async def get_cve(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
):
    from app.services.threat_intelligence_service import get_cve_by_id

    cve = await get_cve_by_id(db, cve_id)
    if not cve:
        return SuccessResponse(data=None, message=f"CVE '{cve_id}' not found")
    return SuccessResponse(data=_cve_to_response(cve), message="CVE retrieved")


def _cve_to_response(cve) -> CVEResponse:
    return CVEResponse(
        id=cve.id,
        vuln_id=cve.vuln_id,
        cve_id=cve.cve_id,
        description=cve.description,
        cvss_v2=cve.cvss_v2,
        cvss_v3=cve.cvss_v3,
        cvss_score=cve.cvss_score,
        cvss_vector=cve.cvss_vector,
        cvss_severity=cve.cvss_severity,
        base_score=cve.base_score,
        exploitability_score=cve.exploitability_score,
        impact_score=cve.impact_score,
        cwe_id=cve.cwe_id,
        exploit_available=cve.exploit_available,
        metasploit_module=cve.metasploit_module,
        reference_urls=cve.reference_urls,
        published_date=cve.published_date,
        last_modified=cve.last_modified,
        epss_score=cve.epss_score,
        kev_status=cve.kev_status,
        source=cve.source,
        vendor=cve.vendor,
        product=cve.product,
        affected_versions=cve.affected_versions,
        remediation_priority=cve.remediation_priority,
        created_at=cve.created_at,
        updated_at=cve.updated_at,
    )
