import uuid
from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel, Field


class ScanBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    scan_type: str = Field(
        ...,
        pattern="^(host_discovery|port_scan|service_enum|vuln_scan|full_assessment)$",
    )
    target: str = Field(..., min_length=1)


class ScanCreate(ScanBase):
    parameters: Optional[Dict] = None


class ScanResponse(ScanBase):
    id: uuid.UUID
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    parameters: Optional[Dict] = None
    summary: Optional[Dict] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
