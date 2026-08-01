import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class Packet(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "packets"

    capture_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("packet_captures.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False, default="Other")
    length: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    info: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)


class Conversation(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "conversations"

    capture_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("packet_captures.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False, default="Other")
    packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
