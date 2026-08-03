from typing import List

from pydantic import BaseModel, Field

from app.schemas.auth import UserResponse


class UserListResponse(BaseModel):
    items: List[UserResponse]
    total: int
    page: int
    per_page: int
    total_pages: int


class UserStatusUpdate(BaseModel):
    status: str = Field(..., description="active, inactive, or disabled")


class UserRoleUpdate(BaseModel):
    role: str = Field(..., description="administrator, security_analyst, or viewer")


class UserPasswordReset(BaseModel):
    password: str = Field(..., min_length=8, description="New password (min 8 characters)")
