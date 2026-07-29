import uuid
from typing import Optional

from sqlalchemy import BigInteger, Boolean, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class Report(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "reports"

    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(20), nullable=False)
    format: Mapped[str] = mapped_column(String(10), nullable=False)
    filepath: Mapped[str] = mapped_column(Text, nullable=False)
    file_size: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    include_exec_summary: Mapped[bool] = mapped_column(Boolean, default=True)
    include_technical: Mapped[bool] = mapped_column(Boolean, default=True)
    include_recommendations: Mapped[bool] = mapped_column(Boolean, default=True)
    generated_by: Mapped[str] = mapped_column(
        String(255), default="system"
    )
