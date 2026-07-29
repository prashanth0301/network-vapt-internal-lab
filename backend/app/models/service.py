import uuid
from typing import Optional

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin


class Service(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "services"

    port_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    extra_info: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tunnel: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    normalized_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    normalized_product: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    normalized_version: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    confidence: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    port: Mapped["Port"] = relationship("Port", back_populates="services")
