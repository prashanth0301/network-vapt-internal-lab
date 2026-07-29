import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ArtifactResponse(BaseModel):
    id: str
    assessment_id: str
    stage_name: str
    scanner_name: Optional[str] = None
    command: Optional[str] = None
    parameters: Optional[dict] = None
    scanner_version: Optional[str] = None
    target: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration: Optional[float] = None
    status: str
    error_message: Optional[str] = None
    artifact_path: str
    output_type: Optional[str] = None
    hash: Optional[str] = None
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}


class ArtifactListResponse(BaseModel):
    data: list[ArtifactResponse]
    pagination: dict


class ArtifactContentResponse(BaseModel):
    id: str
    stage_name: str
    content_type: str
    content: Any
    filename: str
