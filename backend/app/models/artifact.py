import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class Artifact(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "artifacts"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    stage_name: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )
    exploit_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("exploits.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    scanner_name: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    command: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    parameters: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    scanner_version: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    target: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    start_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    end_time: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="pending", index=True
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    artifact_path: Mapped[str] = mapped_column(Text, nullable=False)
    output_type: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True
    )
    hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )

    exploit: Mapped[Optional["Exploit"]] = relationship(
        "Exploit", back_populates="artifacts"
    )
