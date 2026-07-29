import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import INET, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.exploit import Exploit
    from app.models.port import Port
    from app.models.vulnerability import Vulnerability


class Host(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "hosts"

    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    ip_address: Mapped[str] = mapped_column(INET, nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(MACADDR, nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    os_accuracy: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), default="unknown", index=True
    )
    latency: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    ports: Mapped[List["Port"]] = relationship(
        "Port", back_populates="host", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="host", cascade="all, delete-orphan"
    )
    exploits: Mapped[List["Exploit"]] = relationship(
        "Exploit", back_populates="host", cascade="all, delete-orphan"
    )
