from typing import Optional

from fastapi import APIRouter, Depends, Query
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.schemas.common import PaginatedResponse, SuccessResponse
from app.schemas.vulnerability import (
    VulnerabilityResponse,
    VulnerabilityScanRequest,
    VulnerabilitySummaryResponse,
)
from app.services.assessment import assessment_manager
from app.services.vulnerability_assessment_service import (
    get_all_vulnerabilities,
    get_all_scanners,
    get_vulnerabilities_by_assessment,
    get_vulnerabilities_by_host,
    get_vulnerability_by_id,
    get_vulnerability_summary,
)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=PaginatedResponse[VulnerabilityResponse])
async def list_vulnerabilities(
    severity: Optional[str] = Query(None, description="Filter by severity (Critical/High/Medium/Low/Info)"),
    host_id: Optional[str] = Query(None, description="Filter by host UUID"),
    service_name: Optional[str] = Query(None, description="Filter by service name"),
    search: Optional[str] = Query(None, description="Search in title and description"),
    sort_by: str = Query("severity", description="Sort field"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    vulns, total = await get_all_vulnerabilities(
        session=db,
        page=page,
        per_page=per_page,
        severity=severity,
        host_id=host_id,
        service_name=service_name,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    items = [_vuln_to_response(v) for v in vulns]
    total_pages = max(1, (total + per_page - 1) // per_page)
    return PaginatedResponse(
        data=items,
        pagination={"page": page, "per_page": per_page, "total": total, "total_pages": total_pages},
    )


@router.get("/{vuln_id}", response_model=SuccessResponse[VulnerabilityResponse])
async def get_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
):
    vuln = await get_vulnerability_by_id(db, vuln_id)
    if not vuln:
        return SuccessResponse(data=None, message=f"Vulnerability '{vuln_id}' not found")
    return SuccessResponse(data=_vuln_to_response(vuln), message="Vulnerability retrieved")


@router.get("/by-host/{host_id}", response_model=SuccessResponse[list[VulnerabilityResponse]])
async def list_vulnerabilities_by_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
):
    vulns = await get_vulnerabilities_by_host(db, host_id)
    items = [_vuln_to_response(v) for v in vulns]
    return SuccessResponse(data=items, message=f"Found {len(items)} vulnerabilities for host")


@router.get("/by-assessment/{assessment_id}", response_model=SuccessResponse[list[VulnerabilityResponse]])
async def list_vulnerabilities_by_assessment(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
):
    vulns = await get_vulnerabilities_by_assessment(db, assessment_id)
    items = [_vuln_to_response(v) for v in vulns]
    return SuccessResponse(data=items, message=f"Found {len(items)} vulnerabilities for assessment")


@router.get("/summary", response_model=SuccessResponse[VulnerabilitySummaryResponse])
async def vulnerability_summary(
    db: AsyncSession = Depends(get_db),
):
    summary = await get_vulnerability_summary(db)
    return SuccessResponse(data=summary, message="Vulnerability summary retrieved")


@router.get("/scanners", response_model=SuccessResponse[list[str]])
async def list_scanners(
    db: AsyncSession = Depends(get_db),
):
    scanners = await get_all_scanners(db)
    return SuccessResponse(data=scanners, message=f"Found {len(scanners)} scanners")


@router.post("/scan", response_model=SuccessResponse[dict])
async def start_vulnerability_scan(
    body: VulnerabilityScanRequest,
    db: AsyncSession = Depends(get_db),
):
    assessment = assessment_manager.create_assessment(
        name=f"Vulnerability Assessment - {body.target}",
        scan_type="vulnerability_assessment",
        target=body.target,
        parameters={
            "scan_profile": body.scan_profile,
            "ports": body.ports,
        },
    )

    logger.info(
        "Created vulnerability assessment: {id} for target {target}",
        id=assessment.id,
        target=body.target,
    )

    return SuccessResponse(
        data={
            "assessment_id": assessment.id,
            "target": body.target,
            "status": assessment.status.value,
            "message": "Vulnerability assessment created. Use GET /assessments/{id} to track progress.",
        },
        message="Vulnerability scan initiated",
    )


def _vuln_to_response(vuln) -> VulnerabilityResponse:
    host_ip = None
    host_name = None
    port_number = None
    port_protocol = None

    if vuln.host:
        host_ip = vuln.host.ip_address
        host_name = vuln.host.hostname
    if vuln.port:
        port_number = vuln.port.port
        port_protocol = vuln.port.protocol

    return VulnerabilityResponse(
        id=vuln.id,
        host_id=vuln.host_id,
        scan_id=vuln.scan_id,
        port_id=vuln.port_id,
        name=vuln.name,
        description=vuln.description,
        solution=vuln.solution,
        risk_score=vuln.risk_score,
        severity=vuln.severity,
        cvss_vector=vuln.cvss_vector,
        cve_ids=vuln.cve_ids,
        plugin_id=vuln.plugin_id,
        plugin_output=vuln.plugin_output,
        scanner_name=vuln.scanner_name,
        scanner_id=vuln.scanner_id,
        status=vuln.status,
        affected_product=vuln.affected_product,
        affected_version=vuln.affected_version,
        evidence=vuln.evidence,
        raw_scanner_output=vuln.raw_scanner_output,
        created_at=vuln.created_at,
        updated_at=vuln.updated_at,
        host_ip=host_ip,
        host_name=host_name,
        port_number=port_number,
        port_protocol=port_protocol,
    )
