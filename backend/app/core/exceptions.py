from typing import Any, Dict, Optional


class VAPTException(Exception):
    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"
    message: str = "An unexpected error occurred"

    def __init__(
        self,
        message: Optional[str] = None,
        status_code: Optional[int] = None,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        if message:
            self.message = message
        if status_code:
            self.status_code = status_code
        if error_code:
            self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
        }


class NotFoundException(VAPTException):
    status_code = 404
    error_code = "NOT_FOUND"

    def __init__(self, entity: str, entity_id: str):
        super().__init__(
            message=f"{entity} with ID '{entity_id}' not found",
            error_code="NOT_FOUND",
        )


class ValidationException(VAPTException):
    status_code = 422
    error_code = "VALIDATION_ERROR"

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            details=details,
        )


class ScanException(VAPTException):
    status_code = 500
    error_code = "SCAN_ERROR"

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="SCAN_ERROR",
            details=details,
        )


class ToolException(VAPTException):
    status_code = 502
    error_code = "TOOL_ERROR"

    def __init__(self, tool: str, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"{tool} error: {message}",
            error_code="TOOL_ERROR",
            details={"tool": tool, **(details or {})},
        )


class DatabaseException(VAPTException):
    status_code = 500
    error_code = "DATABASE_ERROR"

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="DATABASE_ERROR",
            details=details,
        )
