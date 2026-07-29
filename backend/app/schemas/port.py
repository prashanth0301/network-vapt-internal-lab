import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class ServiceResponse(BaseModel):
    id: uuid.UUID
    port_id: uuid.UUID
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    tunnel: Optional[str] = None
    banner: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PortResponse(BaseModel):
    id: uuid.UUID
    host_id: uuid.UUID
    port: int
    protocol: str
    state: str
    reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    services: list[ServiceResponse] = []

    model_config = {"from_attributes": True}


class PortScanRequest(BaseModel):
    target: str = Field(..., min_length=1, description="Target IP address or CIDR range")
    scan_type: str = Field(
        default="tcp_syn",
        pattern="^(tcp_syn|tcp_connect|udp_scan|version_detection)$",
    )
    scan_profile: str = Field(
        default="top_ports",
        pattern="^(top_ports|custom_range|all_ports)$",
    )
    ports: Optional[str] = Field(None, description="Port range for custom_range profile (e.g. '22,80,443' or '1-1024')")
    extra_args: Optional[list[str]] = Field(None, description="Extra Nmap arguments")
