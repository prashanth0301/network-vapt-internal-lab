from typing import Optional

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class Setting(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
