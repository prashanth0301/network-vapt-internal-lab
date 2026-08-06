import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.services.auth import get_current_user
from app.schemas.common import ErrorResponse, SuccessResponse
from app.schemas.host import (
    HostDetailsResponse,
    HostDiscoverRequest,
    HostResponse,
    HostUpdate,
)
from app.services.host_details_service import get_host_details
from app.services.host_discovery_service import (
    delete_host,
    get_all_hosts,
    get_host_by_id,
    get_host_summary,
)

router = APIRouter(
    prefix="/hosts",
    tags=["Hosts"],
    dependencies=[Depends(get_current_user)],
)


@router.get(
    "",
    response_model=SuccessResponse[list[HostResponse]],
    summary="List discovered hosts",
)
async def list_hosts(
    status: Optional[str] = Query(None, description="Filter by host status"),
    alive_only: bool = Query(False, description="Show only alive hosts"),
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    search: Optional[str] = Query(None, description="Search hosts"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
):
    hosts, total = await get_all_hosts(
        session=db,
        page=page,
        per_page=per_page,
        status=status,
        alive_only=alive_only,
        assessment_id=assessment_id,
        search=search,
    )
    items = [
        HostResponse(
            id=h.id,
            scan_id=h.scan_id,
            ip_address=h.ip_address,
            hostname=h.hostname,
            mac_address=h.mac_address,
            vendor=h.vendor,
            os_name=h.os_name,
            os_version=h.os_version,
            os_accuracy=h.os_accuracy,
            status=h.status,
            latency=h.latency,
            is_alive=h.is_alive,
            first_seen=h.first_seen,
            last_seen=h.last_seen,
            created_at=h.created_at,
            updated_at=h.updated_at,
        )
        for h in hosts
    ]
    return SuccessResponse(
        data=items,
        message=f"Found {total} hosts",
    )


@router.get(
    "/summary",
    response_model=SuccessResponse[dict],
    summary="Get host summary statistics",
)
async def hosts_summary(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    db: AsyncSession = Depends(get_db),
):
    summary = await get_host_summary(db, assessment_id)
    return SuccessResponse(
        data=summary,
        message="Host summary retrieved",
    )


@router.get(
    "/{host_id}/details",
    response_model=SuccessResponse[HostDetailsResponse],
    summary="Get consolidated host details",
    responses={404: {"model": ErrorResponse, "description": "Host not found"}},
)
async def host_details(
    host_id: str,
    db: AsyncSession = Depends(get_db),
):
    details = await get_host_details(db, host_id)
    if not details:
        raise HTTPException(status_code=404, detail=f"Host '{host_id}' not found")
    host = details.pop("host")
    return SuccessResponse(
        data=HostDetailsResponse(
            host=HostResponse.model_validate(host, from_attributes=True),
            **details,
        ),
        message="Host details retrieved",
    )


@router.get(
    "/{host_id}",
    response_model=SuccessResponse[Optional[HostResponse]],
    summary="Get host details",
    responses={404: {"model": ErrorResponse, "description": "Host not found"}},
)
async def get_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
):
    host = await get_host_by_id(db, host_id)
    if not host:
        return SuccessResponse(
            data=None,
            message=f"Host '{host_id}' not found",
        )
    return SuccessResponse(
        data=HostResponse(
            id=host.id,
            scan_id=host.scan_id,
            ip_address=host.ip_address,
            hostname=host.hostname,
            mac_address=host.mac_address,
            vendor=host.vendor,
            os_name=host.os_name,
            os_version=host.os_version,
            os_accuracy=host.os_accuracy,
            status=host.status,
            latency=host.latency,
            is_alive=host.is_alive,
            first_seen=host.first_seen,
            last_seen=host.last_seen,
            created_at=host.created_at,
            updated_at=host.updated_at,
        ),
        message="Host retrieved",
    )


@router.delete(
    "/{host_id}",
    response_model=SuccessResponse[dict],
    summary="Delete a host record",
)
async def remove_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
):
    deleted = await delete_host(db, host_id)
    if not deleted:
        return SuccessResponse(
            data={"id": host_id},
            message=f"Host '{host_id}' not found",
        )
    return SuccessResponse(
        data={"id": host_id},
        message="Host deleted",
    )


@router.post(
    "/discover",
    response_model=SuccessResponse[dict],
    summary="Run host discovery scan",
)
async def discover_hosts(
    body: HostDiscoverRequest,
    db: AsyncSession = Depends(get_db),
):
    from app.services.assessment import assessment_manager

    assessment = assessment_manager.create_assessment(
        name=f"Host Discovery - {body.target}",
        scan_type="host_discovery",
        target=body.target,
        parameters={"scan_type": body.scan_type},
    )
    await assessment_manager.persist_assessment(assessment.id)

    logger.info(
        "Assessment created: {id} - Host Discovery for target {target}",
        id=assessment.id,
        target=body.target,
    )

    record = await assessment_manager.start_assessment(assessment.id)
    await assessment_manager.persist_assessment(assessment.id)
    logger.info(
        "Assessment started: {id} - Host Discovery pipeline launched",
        id=assessment.id,
    )

    return SuccessResponse(
        data={
            "assessment_id": assessment.id,
            "target": body.target,
            "scan_type": body.scan_type,
            "status": record.status.value,
        },
        message="Discovery started",
    )
