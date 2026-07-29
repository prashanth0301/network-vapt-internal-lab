from fastapi import APIRouter

from app.api.v1.artifacts import router as artifacts_router
from app.api.v1.assessments import router as assessments_router
from app.api.v1.cves import router as cves_router
from app.api.v1.exploits import router as exploits_router
from app.api.v1.health import router as health_router
from app.api.v1.hosts import router as hosts_router
from app.api.v1.ports import router as ports_router
from app.api.v1.services import router as services_router
from app.api.v1.vulnerabilities import router as vulnerabilities_router

v1_router = APIRouter()
v1_router.include_router(health_router, prefix="/health", tags=["Health"])
v1_router.include_router(artifacts_router)
v1_router.include_router(assessments_router)
v1_router.include_router(cves_router)
v1_router.include_router(exploits_router)
v1_router.include_router(hosts_router)
v1_router.include_router(ports_router)
v1_router.include_router(services_router)
v1_router.include_router(vulnerabilities_router)
