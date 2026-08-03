import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.core.dependencies import get_db
from app.models.exploit import Exploit
from app.models.host import Host
from app.models.packet_capture import PacketCapture
from app.models.port import Port
from app.models.report import Report
from app.models.scan import Scan
from app.models.service import Service
from app.models.vulnerability import Vulnerability
from app.schemas.assessment import (
    AssessmentCreate,
    AssessmentProgress,
    AssessmentResponse,
    AssessmentStatisticsResponse,
    AssessmentSummaryResponse,
    PipelineResponse,
)
from app.schemas.common import (
    ErrorResponse,
    SuccessResponse,
)
from app.services.assessment import assessment_manager
from app.services.assessment.exceptions import (
    AssessmentAlreadyRunningError,
    AssessmentInvalidTransitionError,
    AssessmentNotFoundError,
)
from app.services.assessment.lifecycle import AssessmentStatus
from app.services.assessment_cleanup import delete_assessment_cascade

router = APIRouter(prefix="/assessments", tags=["Assessments"])


def _record_duration_seconds(
    started_at: Optional[datetime],
    completed_at: Optional[datetime],
    status: str,
) -> Optional[int]:
    if not started_at:
        return None
    end = completed_at or (datetime.now(timezone.utc) if status in ("running", "pending") else None)
    if not end:
        return None
    return max(0, int((end - started_at).total_seconds()))


def _record_progress_percent(record) -> float:
    if record.status == AssessmentStatus.COMPLETED:
        return 100.0
    progress = assessment_manager.get_assessment_progress(record.id)
    if progress and progress.get("overall_progress") is not None:
        return float(progress["overall_progress"])
    return 0.0


def _response_from_record(record) -> AssessmentResponse:
    return AssessmentResponse(
        id=record.id,
        name=record.name,
        scan_type=record.scan_type,
        target=record.target,
        status=record.status.value,
        parameters=record.parameters,
        created_at=record.created_at.isoformat(),
        updated_at=record.updated_at.isoformat(),
        started_at=record.started_at.isoformat() if record.started_at else None,
        completed_at=record.completed_at.isoformat() if record.completed_at else None,
        duration_seconds=_record_duration_seconds(
            record.started_at, record.completed_at, record.status.value
        ),
        progress_percent=_record_progress_percent(record),
    )


def _progress_from_status_data(status_data: dict) -> Optional[AssessmentProgress]:
    progress_data = status_data.get("progress")
    if not progress_data:
        return None
    return AssessmentProgress(
        overall_progress=progress_data["overall_progress"],
        total_weight=progress_data["total_weight"],
        stages=[
            {
                "stage_name": s["stage_name"],
                "display_name": s["display_name"],
                "weight": s["weight"],
                "status": s["status"],
                "progress": s["progress"],
                "started_at": s["started_at"],
                "completed_at": s["completed_at"],
                "error_message": s["error_message"],
                "summary": s["summary"],
            }
            for s in progress_data["stages"]
        ],
        started_at=progress_data["started_at"],
        completed_at=progress_data["completed_at"],
    )


async def _severity_counts_by_assessment(
    db, assessment_ids: list[str]
) -> dict[str, dict[str, int]]:
    if not assessment_ids:
        return {}
    result = await db.execute(
        select(
            Vulnerability.scan_id,
            Vulnerability.severity,
            func.count(Vulnerability.id),
        )
        .where(Vulnerability.scan_id.in_([uuid.UUID(aid) for aid in assessment_ids]))
        .group_by(Vulnerability.scan_id, Vulnerability.severity)
    )
    counts: dict[str, dict[str, int]] = {}
    for scan_id, severity, count in result:
        counts.setdefault(str(scan_id), {})[severity or "Unknown"] = count
    return counts


@router.post(
    "",
    response_model=SuccessResponse[AssessmentResponse],
    status_code=201,
    summary="Create a new assessment",
    responses={
        400: {"model": ErrorResponse, "description": "Validation error"},
    },
)
async def create_assessment(
    body: AssessmentCreate,
    db=Depends(get_db),
):
    record = assessment_manager.create_assessment(
        name=body.name,
        scan_type=body.scan_type,
        target=body.target,
        parameters=body.parameters,
    )
    await assessment_manager.persist_assessment(record.id)
    return SuccessResponse(
        data=_response_from_record(record),
        message="Assessment created successfully",
    )


@router.get(
    "",
    response_model=SuccessResponse[list[AssessmentResponse]],
    summary="List all assessments",
)
async def list_assessments(
    status: Optional[str] = Query(None, description="Filter by status"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    search: Optional[str] = Query(None, description="Search name or target"),
    target: Optional[str] = Query(None, description="Filter by target"),
    date_from: Optional[datetime] = Query(None, description="Earliest created_at (inclusive)"),
    date_to: Optional[datetime] = Query(None, description="Latest created_at (inclusive, whole day)"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    db=Depends(get_db),
):
    records, total = await assessment_manager.list_assessments_persisted(
        status=status,
        scan_type=scan_type,
        search=search,
        target=target,
        date_from=(
            date_from.replace(tzinfo=timezone.utc)
            if date_from and date_from.tzinfo is None
            else date_from
        ),
        date_to=(
            date_to.replace(tzinfo=timezone.utc)
            if date_to and date_to.tzinfo is None
            else date_to
        ),
        page=page,
        per_page=per_page,
    )
    severity_counts = await _severity_counts_by_assessment(
        db, [r.id for r in records]
    )
    items = []
    for r in records:
        item = _response_from_record(r)
        item.severity_counts = severity_counts.get(r.id, {})
        items.append(item)
    return SuccessResponse(
        data=items,
        message=f"Found {total} assessments",
    )


@router.get(
    "/statistics",
    response_model=SuccessResponse[AssessmentStatisticsResponse],
    summary="Get assessment statistics",
)
async def assessment_statistics(
    db=Depends(get_db),
):
    counts = await assessment_manager.get_status_counts()
    stats = AssessmentStatisticsResponse(
        total=sum(counts.values()),
        by_status=counts,
        success_count=counts.get("completed", 0),
        failure_count=counts.get("failed", 0),
        active_count=counts.get("running", 0) + counts.get("pending", 0),
    )
    return SuccessResponse(
        data=stats,
        message="Assessment statistics retrieved",
    )


@router.get(
    "/{assessment_id}",
    response_model=SuccessResponse[AssessmentResponse],
    summary="Get assessment details with progress",
    responses={
        404: {"model": ErrorResponse, "description": "Assessment not found"},
    },
)
async def get_assessment(
    assessment_id: str,
    db=Depends(get_db),
):
    status_data = await assessment_manager.get_assessment_status_persisted(
        assessment_id
    )

    severity = await _severity_counts_by_assessment(db, [assessment_id])

    return SuccessResponse(
        data=AssessmentResponse(
            id=status_data["id"],
            name=status_data["name"],
            scan_type=status_data["scan_type"],
            target=status_data["target"],
            status=status_data["status"],
            parameters=status_data["parameters"],
            created_at=status_data["created_at"],
            updated_at=status_data["updated_at"],
            started_at=status_data["started_at"],
            completed_at=status_data["completed_at"],
            error_message=status_data.get("error_message"),
            duration_seconds=_record_duration_seconds(
                datetime.fromisoformat(status_data["started_at"])
                if status_data.get("started_at")
                else None,
                datetime.fromisoformat(status_data["completed_at"])
                if status_data.get("completed_at")
                else None,
                status_data["status"],
            ),
            progress=_progress_from_status_data(status_data),
            pipeline=status_data.get("pipeline"),
            severity_counts=severity.get(assessment_id, {}),
        ),
        message="Assessment retrieved successfully",
    )


@router.get(
    "/{assessment_id}/summary",
    response_model=SuccessResponse[AssessmentSummaryResponse],
    summary="Get assessment summary with findings and progress",
    responses={
        404: {"model": ErrorResponse, "description": "Assessment not found"},
    },
)
async def get_assessment_summary(
    assessment_id: str,
    db=Depends(get_db),
):
    status_data = await assessment_manager.get_assessment_status_persisted(
        assessment_id
    )

    severity_counts: dict[str, int] = {}
    for severity, count in (
        await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.scan_id == uuid.UUID(assessment_id))
            .group_by(Vulnerability.severity)
        )
    ).all():
        severity_counts[severity or "Unknown"] = count

    scan_uid = uuid.UUID(assessment_id)
    host_ids = select(Host.id).where(Host.scan_id == scan_uid)
    port_ids = select(Port.id).where(Port.host_id.in_(host_ids))
    service_ids = select(Service.id).where(Service.port_id.in_(port_ids))

    hosts_count = (
        await db.scalar(select(func.count()).select_from(Host).where(Host.scan_id == scan_uid))
    ) or 0
    ports_count = (
        await db.scalar(select(func.count()).select_from(Port).where(Port.host_id.in_(host_ids)))
    ) or 0
    services_count = (
        await db.scalar(select(func.count()).select_from(Service).where(Service.port_id.in_(port_ids)))
    ) or 0
    exploits_count = (
        await db.scalar(select(func.count()).select_from(Exploit).where(Exploit.host_id.in_(host_ids)))
    ) or 0
    reports_count = (
        await db.scalar(select(func.count()).select_from(Report).where(Report.scan_id == scan_uid))
    ) or 0
    captures_count = (
        await db.scalar(select(func.count()).select_from(PacketCapture).where(PacketCapture.scan_id == scan_uid))
    ) or 0

    return SuccessResponse(
        data=AssessmentSummaryResponse(
            id=status_data["id"],
            name=status_data["name"],
            scan_type=status_data["scan_type"],
            target=status_data["target"],
            status=status_data["status"],
            parameters=status_data["parameters"],
            created_at=status_data["created_at"],
            updated_at=status_data["updated_at"],
            started_at=status_data["started_at"],
            completed_at=status_data["completed_at"],
            error_message=status_data.get("error_message"),
            duration_seconds=_record_duration_seconds(
                datetime.fromisoformat(status_data["started_at"])
                if status_data.get("started_at")
                else None,
                datetime.fromisoformat(status_data["completed_at"])
                if status_data.get("completed_at")
                else None,
                status_data["status"],
            ),
            progress_percent=(
                100.0
                if status_data["status"] == AssessmentStatus.COMPLETED.value
                else 0.0
            ),
            progress=_progress_from_status_data(status_data),
            pipeline=status_data.get("pipeline"),
            severity_counts=severity_counts,
            total_vulnerabilities=sum(severity_counts.values()),
            hosts_count=hosts_count,
            ports_count=ports_count,
            services_count=services_count,
            reports_count=reports_count,
            exploits_count=exploits_count,
            captures_count=captures_count,
        ),
        message="Assessment summary retrieved",
    )


@router.post(
    "/{assessment_id}/clone",
    response_model=SuccessResponse[AssessmentResponse],
    status_code=201,
    summary="Clone an assessment",
    responses={
        404: {"model": ErrorResponse, "description": "Assessment not found"},
    },
)
async def clone_assessment(
    assessment_id: str,
    db=Depends(get_db),
):
    source = await assessment_manager.get_assessment_status_persisted(
        assessment_id
    )
    record = assessment_manager.create_assessment(
        name=f"{source['name']} (clone)",
        scan_type=source["scan_type"],
        target=source["target"],
        parameters=source.get("parameters") or {},
    )
    await assessment_manager.persist_assessment(record.id)
    return SuccessResponse(
        data=_response_from_record(record),
        message="Assessment cloned successfully",
    )


@router.post(
    "/{assessment_id}/start",
    response_model=SuccessResponse[AssessmentResponse],
    summary="Start an assessment",
    responses={
        404: {"model": ErrorResponse, "description": "Assessment not found"},
        409: {"model": ErrorResponse, "description": "Already running"},
    },
)
async def start_assessment(
    assessment_id: str,
    db=Depends(get_db),
):
    record = await assessment_manager.start_assessment(assessment_id)
    await assessment_manager.persist_assessment(assessment_id)
    return SuccessResponse(
        data=_response_from_record(record),
        message="Assessment started",
    )


@router.post(
    "/{assessment_id}/cancel",
    response_model=SuccessResponse[AssessmentResponse],
    summary="Cancel a running assessment",
    responses={
        404: {"model": ErrorResponse, "description": "Assessment not found"},
    },
)
async def cancel_assessment(
    assessment_id: str,
    db=Depends(get_db),
):
    record = assessment_manager.cancel_assessment(assessment_id)
    await assessment_manager.persist_assessment(assessment_id)
    return SuccessResponse(
        data=_response_from_record(record),
        message="Assessment cancelled",
    )


@router.delete(
    "/{assessment_id}",
    response_model=SuccessResponse[dict],
    summary="Delete an assessment and all associated data",
    responses={
        404: {"model": ErrorResponse, "description": "Assessment not found"},
    },
)
async def delete_assessment(
    assessment_id: str,
    db=Depends(get_db),
):
    try:
        uid = uuid.UUID(assessment_id)
    except ValueError:
        raise AssessmentNotFoundError(assessment_id)

    try:
        assessment_manager.get_assessment(assessment_id)
    except AssessmentNotFoundError:
        scan = await db.scalar(select(Scan.id).where(Scan.id == uid))
        if scan is None:
            raise AssessmentNotFoundError(assessment_id)

    counts = await delete_assessment_cascade(db, assessment_id)
    return SuccessResponse(
        data={"id": assessment_id, "deleted": counts},
        message="Assessment and associated reports/artifacts deleted",
    )


@router.get(
    "/pipelines/{scan_type}",
    response_model=SuccessResponse[PipelineResponse],
    summary="Get pipeline stages for a scan type",
)
async def get_pipeline_stages(
    scan_type: str,
    db=Depends(get_db),
):
    stages = assessment_manager.get_pipeline_stages(scan_type)
    return SuccessResponse(
        data=PipelineResponse(scan_type=scan_type, stages=stages),
        message=f"Pipeline for '{scan_type}'",
    )
