from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.core.dependencies import get_db
from app.schemas.assessment import (
    AssessmentCreate,
    AssessmentResponse,
    AssessmentStatusResponse,
    PipelineResponse,
)
from app.schemas.common import (
    ErrorResponse,
    PaginatedResponse,
    SuccessResponse,
)
from app.services.assessment import assessment_manager
from app.services.assessment.exceptions import (
    AssessmentAlreadyRunningError,
    AssessmentInvalidTransitionError,
    AssessmentNotFoundError,
)

router = APIRouter(prefix="/assessments", tags=["Assessments"])


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
        data=AssessmentResponse(
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
        ),
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
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    db=Depends(get_db),
):
    records, total = await assessment_manager.list_assessments_persisted(
        status=status,
        scan_type=scan_type,
        page=page,
        per_page=per_page,
    )
    items = [
        AssessmentResponse(
            id=r.id,
            name=r.name,
            scan_type=r.scan_type,
            target=r.target,
            status=r.status.value,
            parameters=r.parameters,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
            started_at=r.started_at.isoformat() if r.started_at else None,
            completed_at=r.completed_at.isoformat() if r.completed_at else None,
        )
        for r in records
    ]
    return SuccessResponse(
        data=items,
        message=f"Found {total} assessments",
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

    progress_data = status_data.get("progress")
    pipeline_data = status_data.get("pipeline")

    progress_model = None
    if progress_data:
        from app.schemas.assessment import AssessmentProgress

        progress_model = AssessmentProgress(
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
            progress=progress_model,
            pipeline=pipeline_data,
        ),
        message="Assessment retrieved successfully",
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
        data=AssessmentResponse(
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
        ),
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
        data=AssessmentResponse(
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
        ),
        message="Assessment cancelled",
    )


@router.delete(
    "/{assessment_id}",
    response_model=SuccessResponse[dict],
    summary="Delete an assessment",
    responses={
        404: {"model": ErrorResponse, "description": "Assessment not found"},
    },
)
async def delete_assessment(
    assessment_id: str,
    db=Depends(get_db),
):
    deleted = assessment_manager.delete_assessment(assessment_id)
    if not deleted:
        raise AssessmentNotFoundError(assessment_id)
    await assessment_manager.remove_persisted(assessment_id)
    return SuccessResponse(
        data={"id": assessment_id},
        message="Assessment deleted",
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
