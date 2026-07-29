import uuid
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.host import Host
    from app.models.service import Service
    from app.models.vulnerability import Vulnerability


class Port(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "ports"

    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="unknown", index=True)
    reason: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    __table_args__ = (
        UniqueConstraint("host_id", "port", "protocol", name="uq_host_port_protocol"),
    )

    host: Mapped["Host"] = relationship("Host", back_populates="ports")
    services: Mapped[List["Service"]] = relationship(
        "Service", back_populates="port", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="port"
    )
