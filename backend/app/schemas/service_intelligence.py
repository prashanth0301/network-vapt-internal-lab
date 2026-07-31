import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ServiceIntelligenceResponse(BaseModel):
    id: uuid.UUID
    port_id: uuid.UUID
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    tunnel: Optional[str] = None
    protocol: Optional[str] = None
    banner: Optional[str] = None
    normalized_name: Optional[str] = None
    normalized_product: Optional[str] = None
    normalized_version: Optional[str] = None
    category: Optional[str] = None
    confidence: Optional[int] = None
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    port_number: Optional[int] = None
    port_protocol: Optional[str] = None
    host_id: Optional[uuid.UUID] = None
    host_ip: Optional[str] = None
    host_name: Optional[str] = None

    model_config = {"from_attributes": True}


class ServiceEnrichRequest(BaseModel):
    service_ids: Optional[list[uuid.UUID]] = Field(None, description="Specific service IDs to enrich. If empty, all unenriched services are processed.")
    assessment_id: Optional[uuid.UUID] = Field(None, description="Scope bulk enrichment to a specific assessment")
