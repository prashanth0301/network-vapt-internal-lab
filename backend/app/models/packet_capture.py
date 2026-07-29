import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class PacketCapture(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "packet_captures"

    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    filepath: Mapped[str] = mapped_column(Text, nullable=False)
    file_size: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    packet_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    filter: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True
    )
    protocol_stats: Mapped[Optional[dict]] = mapped_column(
        JSONB, nullable=True
    )
    capture_started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    capture_ended_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
