import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, IPvAnyAddress


class HostBase(BaseModel):
    ip_address: IPvAnyAddress
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    status: str = "unknown"


class HostCreate(HostBase):
    scan_id: Optional[uuid.UUID] = None


class HostUpdate(BaseModel):
    hostname: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    status: Optional[str] = None
    is_alive: Optional[bool] = None


class HostResponse(HostBase):
    id: uuid.UUID
    scan_id: Optional[uuid.UUID] = None
    os_accuracy: Optional[int] = None
    latency: Optional[float] = None
    is_alive: bool = False
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class HostDiscoverRequest(BaseModel):
    target: str = Field(
        default="192.168.56.0/24",
        description="Target IP range in CIDR notation",
        pattern=r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$",
    )
    scan_type: str = Field(
        default="ping_sweep",
        pattern="^(ping_sweep|arp_scan|quick_scan)$",
    )
