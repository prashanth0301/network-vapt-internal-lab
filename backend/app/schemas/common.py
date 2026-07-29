from datetime import datetime, timezone
from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PaginationParams(BaseModel):
    page: int = Field(default=1, ge=1, description="Page number")
    per_page: int = Field(
        default=20, ge=1, le=100, description="Items per page"
    )
    sort_by: Optional[str] = Field(default=None, description="Sort field")
    sort_order: str = Field(
        default="desc", pattern="^(asc|desc)$", description="Sort direction"
    )


class PaginationMeta(BaseModel):
    page: int
    per_page: int
    total: int
    total_pages: int


class SuccessResponse(BaseModel, Generic[T]):
    status: str = "success"
    data: T
    message: Optional[str] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ErrorDetail(BaseModel):
    error_code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class ErrorResponse(BaseModel):
    status: str = "error"
    error: ErrorDetail
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class PaginatedResponse(BaseModel, Generic[T]):
    status: str = "success"
    data: List[T]
    pagination: PaginationMeta
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
