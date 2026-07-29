import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.schemas.common import PaginatedResponse, SuccessResponse
from app.schemas.service_intelligence import ServiceEnrichRequest, ServiceIntelligenceResponse
from app.services.assessment import assessment_manager
from app.services.service_intelligence_service import (
    enrich_service,
    get_all_categories,
    get_all_services,
    get_service_by_id,
    get_services_by_assessment,
    get_services_by_host,
)

router = APIRouter(prefix="/services", tags=["Services"])


@router.get("", response_model=PaginatedResponse[ServiceIntelligenceResponse])
async def list_services(
    category: Optional[str] = Query(None, description="Filter by service category"),
    confidence_min: Optional[int] = Query(None, ge=0, le=100, description="Minimum confidence score"),
    search: Optional[str] = Query(None, description="Search in name, product, version"),
    sort_by: str = Query("name", description="Sort field"),
    sort_order: str = Query("asc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    services, total = await get_all_services(
        session=db,
        page=page,
        per_page=per_page,
        category=category,
        confidence_min=confidence_min,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    items = [_service_to_response(s) for s in services]
    total_pages = max(1, (total + per_page - 1) // per_page)
    return PaginatedResponse(
        data=items,
        pagination={"page": page, "per_page": per_page, "total": total, "total_pages": total_pages},
    )


@router.get("/{service_id}", response_model=SuccessResponse[ServiceIntelligenceResponse])
async def get_service(
    service_id: str,
    db: AsyncSession = Depends(get_db),
):
    service = await get_service_by_id(db, service_id)
    if not service:
        return SuccessResponse(data=None, message=f"Service '{service_id}' not found")
    return SuccessResponse(data=_service_to_response(service), message="Service retrieved")


@router.get("/by-host/{host_id}", response_model=SuccessResponse[list[ServiceIntelligenceResponse]])
async def list_services_by_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
):
    services = await get_services_by_host(db, host_id)
    items = [_service_to_response(s) for s in services]
    return SuccessResponse(data=items, message=f"Found {len(items)} services for host")


@router.get("/by-assessment/{assessment_id}", response_model=SuccessResponse[list[ServiceIntelligenceResponse]])
async def list_services_by_assessment(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
):
    services = await get_services_by_assessment(db, assessment_id)
    items = [_service_to_response(s) for s in services]
    return SuccessResponse(data=items, message=f"Found {len(items)} services for assessment")


@router.get("/categories", response_model=SuccessResponse[list[str]])
async def list_categories(
    db: AsyncSession = Depends(get_db),
):
    categories = await get_all_categories(db)
    return SuccessResponse(data=categories, message=f"Found {len(categories)} categories")


@router.post("/enrich", response_model=SuccessResponse[dict])
async def enrich_services(
    body: ServiceEnrichRequest,
    db: AsyncSession = Depends(get_db),
):
    from app.services.service_intelligence_service import get_all_services

    logger.info("Service enrichment requested via API")

    if body.service_ids:
        services_enriched = 0
        for sid in body.service_ids:
            service = await get_service_by_id(db, str(sid))
            if service:
                enrich_service(service)
                db.add(service)
                services_enriched += 1
        await db.commit()
        return SuccessResponse(
            data={"services_enriched": services_enriched},
            message=f"Enriched {services_enriched} services",
        )

    services_result = await get_all_services(session=db, per_page=10000)
    services = services_result[0]
    enriched = 0
    for service in services:
        if not service.normalized_name and not service.category:
            enrich_service(service)
            db.add(service)
            enriched += 1
    await db.commit()
    return SuccessResponse(
        data={"services_enriched": enriched},
        message=f"Enriched {enriched} services",
    )


def _service_to_response(service) -> ServiceIntelligenceResponse:
    port_number = None
    port_protocol = None
    host_id = None
    host_ip = None
    host_name = None

    if service.port:
        port_number = service.port.port
        port_protocol = service.port.protocol
        if service.port.host:
            host_id = service.port.host.id
            host_ip = service.port.host.ip_address
            host_name = service.port.host.hostname

    return ServiceIntelligenceResponse(
        id=service.id,
        port_id=service.port_id,
        name=service.name,
        product=service.product,
        version=service.version,
        extra_info=service.extra_info,
        tunnel=service.tunnel,
        protocol=service.protocol,
        banner=service.banner,
        normalized_name=service.normalized_name,
        normalized_product=service.normalized_product,
        normalized_version=service.normalized_version,
        category=service.category,
        confidence=service.confidence,
        notes=service.notes,
        created_at=service.created_at,
        updated_at=service.updated_at,
        port_number=port_number,
        port_protocol=port_protocol,
        host_id=host_id,
        host_ip=host_ip,
        host_name=host_name,
    )
