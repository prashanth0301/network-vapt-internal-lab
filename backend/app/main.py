import time
import warnings
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from loguru import logger

from app.api.router import api_router
from app.core.config import settings
from app.core.database import close_db, init_db
from app.core.logging import setup_logging
from app.middleware.cors import setup_cors
from app.middleware.error_handler import setup_error_handlers


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting {app_name} v{version}",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
    )
    config_validation = validate_configuration()
    if not config_validation["valid"]:
        logger.error(
            "Configuration validation failed: {errors}",
            errors=config_validation["errors"],
        )
        raise SystemExit(1)

    logger.info("Initializing database connection")
    await init_db()
    logger.info("Database initialized successfully")

    from app.services.host_discovery_service import host_discovery_handler
    from app.services.assessment import assessment_manager
    from app.services.port_scan_service import port_scan_handler
    from app.services.service_intelligence_service import service_intelligence_handler
    from app.services.cve_intelligence_handler import cve_intelligence_handler
    from app.services.exploit_verification_handler import (
        exploit_verification_handler,
    )
    from app.services.vulnerability_assessment_service import (
        vulnerability_assessment_handler,
    )

    assessment_manager.stage_manager.register_handler(
        "host_discovery", host_discovery_handler
    )
    logger.info("Registered host_discovery stage handler")

    assessment_manager.stage_manager.register_handler(
        "port_scan", port_scan_handler
    )
    logger.info("Registered port_scan stage handler")

    assessment_manager.stage_manager.register_handler(
        "service_intelligence", service_intelligence_handler
    )
    logger.info("Registered service_intelligence stage handler")

    assessment_manager.stage_manager.register_handler(
        "vulnerability_assessment", vulnerability_assessment_handler
    )
    logger.info("Registered vulnerability_assessment stage handler")

    assessment_manager.stage_manager.register_handler(
        "cve_intelligence", cve_intelligence_handler
    )
    logger.info("Registered cve_intelligence stage handler")

    assessment_manager.stage_manager.register_handler(
        "exploit_verification", exploit_verification_handler
    )
    logger.info("Registered exploit_verification stage handler")

    logger.info(
        "Application startup complete - {app_name} v{version}",
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
    )
    yield
    logger.info("Shutting down database connection")
    await close_db()
    logger.info("Application shutdown complete")


def validate_configuration() -> dict:
    errors = []
    if not settings.APP_NAME:
        errors.append("APP_NAME is not set")
    if not settings.APP_VERSION:
        errors.append("APP_VERSION is not set")
    if not settings.DATABASE_URL:
        errors.append("DATABASE_URL is not set")
    if not settings.CORS_ORIGINS:
        warnings.warn("CORS_ORIGINS is empty - API may be inaccessible from frontend")
    return {"valid": len(errors) == 0, "errors": errors}


def create_app() -> FastAPI:
    setup_logging()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=settings.APP_DESCRIPTION,
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    setup_cors(app)
    setup_error_handlers(app)

    app.include_router(api_router)

    @app.get("/docs", include_in_schema=False)
    async def custom_swagger_ui_html():
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=f"{settings.APP_NAME} - API Documentation",
            swagger_favicon_url="",
        )

    @app.get("/openapi.json", include_in_schema=False)
    async def custom_openapi():
        return get_openapi(
            title=settings.APP_NAME,
            version=settings.APP_VERSION,
            description=settings.APP_DESCRIPTION,
            routes=app.routes,
        )

    return app


app = create_app()
