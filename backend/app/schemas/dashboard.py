"""Pydantic schemas for the Dashboard summary endpoint."""

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from app.schemas.common import SuccessResponse


class SeveritySlice(BaseModel):
    severity: str
    count: int


class TrendPoint(BaseModel):
    date: str
    count: int


class PortSlice(BaseModel):
    port: int
    count: int
    label: Optional[str] = None


class ServiceSlice(BaseModel):
    name: str
    count: int


class AssessmentItem(BaseModel):
    id: uuid.UUID
    name: str
    scan_type: str
    target: str
    status: str
    created_at: Optional[datetime] = None


class ReportItem(BaseModel):
    id: uuid.UUID
    title: str
    report_type: str
    format: str
    file_size: Optional[int] = None
    created_at: Optional[datetime] = None


class HostVulnItem(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    count: int


class RiskScore(BaseModel):
    score: int
    level: str
    total: int


class ScanDurationStats(BaseModel):
    count: int
    average_seconds: Optional[float] = None
    min_seconds: Optional[float] = None
    max_seconds: Optional[float] = None


class ActivityItem(BaseModel):
    action: str
    user: str
    timestamp: Optional[datetime] = None


class DashboardTotals(BaseModel):
    vulnerabilities: int
    hosts: int
    open_ports: int
    services: int
    reports: int
    assessments: int


class DashboardSummary(BaseModel):
    severity_distribution: List[SeveritySlice]
    vulnerability_trend: List[TrendPoint]
    top_open_ports: List[PortSlice]
    service_distribution: List[ServiceSlice]
    recent_assessments: List[AssessmentItem]
    recent_reports: List[ReportItem]
    top_vulnerable_hosts: List[HostVulnItem]
    risk_score: RiskScore
    critical_count: int
    exploit_available_count: int
    scan_duration_stats: ScanDurationStats
    activity_timeline: List[ActivityItem]
    totals: DashboardTotals


DashboardSummaryResponse = SuccessResponse[DashboardSummary]
