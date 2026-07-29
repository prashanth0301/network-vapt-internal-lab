import traceback
from typing import Union

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from app.core.exceptions import VAPTException


def setup_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(VAPTException)
    async def vapt_exception_handler(
        request: Request, exc: VAPTException
    ) -> JSONResponse:
        logger.error(
            "VAPTException: {error_code} - {message}",
            error_code=exc.error_code,
            message=exc.message,
            extra={"path": str(request.url), "details": exc.details},
        )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": "error",
                "error": exc.to_dict(),
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = []
        for err in exc.errors():
            errors.append(
                {
                    "field": " -> ".join(str(loc) for loc in err.get("loc", [])),
                    "message": err.get("msg", ""),
                    "type": err.get("type", ""),
                }
            )
        logger.warning(
            "Validation error: {errors}",
            errors=errors,
            extra={"path": str(request.url)},
        )
        return JSONResponse(
            status_code=422,
            content={
                "status": "error",
                "error": {
                    "error_code": "VALIDATION_ERROR",
                    "message": "Request validation failed",
                    "details": {"errors": errors},
                },
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            },
        )

    @app.exception_handler(SQLAlchemyError)
    async def sqlalchemy_exception_handler(
        request: Request, exc: SQLAlchemyError
    ) -> JSONResponse:
        logger.error(
            "Database error: {error}",
            error=str(exc),
            extra={"path": str(request.url)},
        )
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error": {
                    "error_code": "DATABASE_ERROR",
                    "message": "A database error occurred",
                },
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.error(
            "Unhandled exception: {error}\n{traceback}",
            error=str(exc),
            traceback=traceback.format_exc(),
            extra={"path": str(request.url)},
        )
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "error": {
                    "error_code": "INTERNAL_ERROR",
                    "message": "An internal error occurred",
                },
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            },
        )
