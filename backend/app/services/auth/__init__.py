from app.services.auth.auth_service import AuthService
from app.services.auth.dependencies import (
    PERMISSIONS,
    get_current_user,
    has_permission,
    require_permissions,
    require_role,
)

auth_service = AuthService()

__all__ = [
    "auth_service",
    "AuthService",
    "PERMISSIONS",
    "get_current_user",
    "has_permission",
    "require_permissions",
    "require_role",
]
