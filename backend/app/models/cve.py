import uuid
from datetime import date
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, Date, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.exploit import Exploit
    from app.models.vulnerability import Vulnerability


class CVE(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "cves"

    vuln_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    cve_id: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )
    cvss_severity: Mapped[Optional[str]] = mapped_column(
        String(20), nullable=True
    )
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    metasploit_module: Mapped[Optional[str]] = mapped_column(
        String(500), nullable=True, index=True
    )
    reference_urls: Mapped[Optional[List[str]]] = mapped_column(
        ARRAY(String), nullable=True
    )
    published_date: Mapped[Optional[date]] = mapped_column(Date, nullable=True)

    vulnerability: Mapped[Optional["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="cves"
    )
    exploits: Mapped[List["Exploit"]] = relationship(
        "Exploit", back_populates="cve", cascade="all, delete-orphan"
    )
