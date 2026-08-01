import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class AssessmentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Assessment name")
    scan_type: str = Field(
        ...,
        pattern="^(host_discovery|port_scan|service_enum|vuln_scan|full_assessment)$",
        description="Type of assessment pipeline to run",
    )
    target: str = Field(..., min_length=1, description="Target IP range or CIDR")
    parameters: Optional[dict] = Field(None, description="Optional scan parameters")


class AssessmentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    parameters: Optional[dict] = None


class StageInfo(BaseModel):
    name: str
    display_name: str
    description: str
    weight: float
    order: int
    is_required: bool
    depends_on: list[str]


class StageProgress(BaseModel):
    stage_name: str
    display_name: str
    weight: float
    status: str
    progress: float
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    summary: Optional[dict] = None


class AssessmentProgress(BaseModel):
    overall_progress: float
    total_weight: float
    stages: list[StageProgress]
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class AssessmentResponse(BaseModel):
    id: str
    name: str
    scan_type: str
    target: str
    status: str
    parameters: Optional[dict] = None
    created_at: str
    updated_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    progress: Optional[AssessmentProgress] = None
    pipeline: Optional[list[StageInfo]] = None

    model_config = {"from_attributes": True}


class AssessmentStatusResponse(BaseModel):
    id: str
    name: str
    status: str
    progress: AssessmentProgress
    pipeline: list[StageInfo]
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class PipelineResponse(BaseModel):
    scan_type: str
    stages: list[StageInfo]


class AssessmentStatisticsResponse(BaseModel):
    total: int
    by_status: dict[str, int]
    success_count: int
    failure_count: int
    active_count: int
