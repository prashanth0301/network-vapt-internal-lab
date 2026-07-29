import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class Scan(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "scans"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="pending", index=True
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    parameters: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    summary: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
