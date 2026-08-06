import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.services.auth import get_current_user
from app.schemas.common import SuccessResponse
from app.schemas.port import PortResponse, PortScanRequest, ServiceResponse
from app.services.assessment import assessment_manager
from app.services.port_scan_service import (
    get_all_ports,
    get_port_by_id,
    get_ports_by_assessment,
    get_ports_by_host,
)

router = APIRouter(
    prefix="/ports",
    tags=["Ports"],
    dependencies=[Depends(get_current_user)],
)


@router.get("", response_model=SuccessResponse[list[PortResponse]])
async def list_ports(
    state: Optional[str] = Query(None, description="Filter by port state"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (tcp/udp)"),
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    ports, total = await get_all_ports(
        session=db, page=page, per_page=per_page, state=state, protocol=protocol,
        assessment_id=assessment_id,
    )
    items = [_port_to_response(p) for p in ports]
    return SuccessResponse(data=items, message=f"Found {total} ports")


@router.get("/{port_id}", response_model=SuccessResponse[PortResponse])
async def get_port(
    port_id: str,
    db: AsyncSession = Depends(get_db),
):
    port = await get_port_by_id(db, port_id)
    if not port:
        raise HTTPException(status_code=404, detail=f"Port '{port_id}' not found")
    return SuccessResponse(data=_port_to_response(port), message="Port retrieved")


@router.get("/by-host/{host_id}", response_model=SuccessResponse[list[PortResponse]])
async def list_ports_by_host(
    host_id: str,
    db: AsyncSession = Depends(get_db),
):
    ports = await get_ports_by_host(db, host_id)
    items = [_port_to_response(p) for p in ports]
    return SuccessResponse(data=items, message=f"Found {len(items)} ports for host")


@router.get("/by-assessment/{assessment_id}", response_model=SuccessResponse[list[PortResponse]])
async def list_ports_by_assessment(
    assessment_id: str,
    db: AsyncSession = Depends(get_db),
):
    ports = await get_ports_by_assessment(db, assessment_id)
    items = [_port_to_response(p) for p in ports]
    return SuccessResponse(data=items, message=f"Found {len(items)} ports for assessment")


@router.post("/scan", response_model=SuccessResponse[dict])
async def start_port_scan(
    body: PortScanRequest,
    db: AsyncSession = Depends(get_db),
):
    assessment = assessment_manager.create_assessment(
        name=f"Port Scan - {body.target}",
        scan_type="port_scan",
        target=body.target,
        parameters={
            "scan_type": body.scan_type,
            "scan_profile": body.scan_profile,
            "ports": body.ports,
            "extra_args": body.extra_args,
        },
    )
    await assessment_manager.persist_assessment(assessment.id)

    logger.info(
        "Assessment created: {id} - Port Scan for target {target}",
        id=assessment.id,
        target=body.target,
    )

    record = await assessment_manager.start_assessment(assessment.id)
    await assessment_manager.persist_assessment(assessment.id)
    logger.info(
        "Assessment started: {id} - Port Scan pipeline launched",
        id=assessment.id,
    )

    return SuccessResponse(
        data={
            "assessment_id": assessment.id,
            "target": body.target,
            "scan_type": body.scan_type,
            "scan_profile": body.scan_profile,
            "status": record.status.value,
        },
        message="Port scan initiated",
    )


def _port_to_response(port) -> PortResponse:
    services = [
        ServiceResponse(
            id=s.id,
            port_id=s.port_id,
            name=s.name,
            product=s.product,
            version=s.version,
            extra_info=s.extra_info,
            tunnel=s.tunnel,
            banner=s.banner,
            created_at=s.created_at,
            updated_at=s.updated_at,
        )
        for s in port.services
    ]

    return PortResponse(
        id=port.id,
        host_id=port.host_id,
        port=port.port,
        protocol=port.protocol,
        state=port.state,
        reason=port.reason,
        created_at=port.created_at,
        updated_at=port.updated_at,
        services=services,
    )
