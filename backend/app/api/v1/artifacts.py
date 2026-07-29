from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.schemas.artifact import (
    ArtifactContentResponse,
    ArtifactListResponse,
    ArtifactResponse,
)
from app.services.artifact_manager import artifact_manager

router = APIRouter(prefix="/artifacts", tags=["Artifacts"])


def _artifact_to_response(artifact) -> ArtifactResponse:
    return ArtifactResponse(
        id=str(artifact.id),
        assessment_id=str(artifact.assessment_id),
        stage_name=artifact.stage_name,
        scanner_name=artifact.scanner_name,
        command=artifact.command,
        parameters=artifact.parameters,
        scanner_version=artifact.scanner_version,
        target=artifact.target,
        start_time=artifact.start_time.isoformat() if artifact.start_time else None,
        end_time=artifact.end_time.isoformat() if artifact.end_time else None,
        duration=artifact.duration,
        status=artifact.status,
        error_message=artifact.error_message,
        artifact_path=artifact.artifact_path,
        output_type=artifact.output_type,
        hash=artifact.hash,
        created_at=artifact.created_at.isoformat() if artifact.created_at else None,
        updated_at=artifact.updated_at.isoformat() if artifact.updated_at else None,
    )


@router.get("/", response_model=ArtifactListResponse)
async def list_artifacts(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment ID"),
    stage_name: Optional[str] = Query(None, description="Filter by stage name"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order"),
    session: AsyncSession = Depends(get_db),
):
    artifacts, total = await artifact_manager.get_artifacts(
        session,
        assessment_id=assessment_id,
        stage_name=stage_name,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return ArtifactListResponse(
        data=[_artifact_to_response(a) for a in artifacts],
        pagination={
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": max(1, (total + per_page - 1) // per_page),
        },
    )


@router.get("/{artifact_id}", response_model=ArtifactResponse)
async def get_artifact(
    artifact_id: str,
    session: AsyncSession = Depends(get_db),
):
    artifact = await artifact_manager.get_artifact_by_id(session, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _artifact_to_response(artifact)


@router.get("/{artifact_id}/files", response_model=list[dict])
async def list_artifact_files(artifact_id: str, session: AsyncSession = Depends(get_db)):
    artifact = await artifact_manager.get_artifact_by_id(session, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    artifact_dir = Path(artifact.artifact_path)
    return artifact_manager.list_artifacts(artifact_dir)


@router.get("/{artifact_id}/download/{filename}", response_model=ArtifactContentResponse)
async def download_artifact_file(
    artifact_id: str,
    filename: str,
    session: AsyncSession = Depends(get_db),
):
    artifact = await artifact_manager.get_artifact_by_id(session, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    artifact_dir = Path(artifact.artifact_path)

    content = artifact_manager.load_artifact(artifact_dir, filename)
    if content is None:
        raise HTTPException(
            status_code=404, detail=f"File '{filename}' not found in artifact"
        )

    content_type = "text"
    if filename.endswith(".json"):
        content_type = "json"
    elif filename.endswith(".xml"):
        content_type = "xml"

    return ArtifactContentResponse(
        id=artifact_id,
        stage_name=artifact.stage_name,
        content_type=content_type,
        content=content,
        filename=filename,
    )
