from datetime import datetime
from typing import Dict

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str
    app_name: str
    database: str
    uptime_seconds: float
    services: Dict[str, str]
    timestamp: str
