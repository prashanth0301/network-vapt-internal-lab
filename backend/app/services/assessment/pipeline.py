from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from app.services.assessment.lifecycle import StageStatus


@dataclass
class StageResult:
    stage_name: str
    status: StageStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    summary: Optional[dict] = None
    error_message: Optional[str] = None
    details: Optional[dict] = None


@dataclass
class PipelineStage:
    name: str
    display_name: str
    description: str
    weight: float
    order: int
    handler: Optional[Callable] = None
    is_required: bool = True
    depends_on: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.weight <= 0:
            raise ValueError(f"Stage '{self.name}' weight must be positive")


STAGES_CONFIG = [
    PipelineStage(
        name="host_discovery",
        display_name="Host Discovery",
        description="Discover live hosts using Nmap ping sweep",
        weight=10.0,
        order=1,
        depends_on=[],
    ),
    PipelineStage(
        name="port_scan",
        display_name="Port Scanning",
        description="Scan discovered hosts for open TCP/UDP ports",
        weight=25.0,
        order=2,
        depends_on=["host_discovery"],
    ),
    PipelineStage(
        name="service_enum",
        display_name="Service Enumeration",
        description="Enumerate service versions and banners",
        weight=15.0,
        order=3,
        depends_on=["port_scan"],
    ),
    PipelineStage(
        name="vuln_scan",
        display_name="Vulnerability Assessment",
        description="Scan for vulnerabilities using OpenVAS/Nessus",
        weight=30.0,
        order=4,
        depends_on=["service_enum"],
    ),
    PipelineStage(
        name="cve_intel",
        display_name="CVE Intelligence",
        description="Correlate findings with CVE database",
        weight=10.0,
        order=5,
        depends_on=["vuln_scan"],
    ),
    PipelineStage(
        name="report",
        display_name="Report Generation",
        description="Generate assessment reports",
        weight=10.0,
        order=6,
        depends_on=["cve_intel"],
    ),
]


class AssessmentPipeline:
    def __init__(self, stages: Optional[list[PipelineStage]] = None):
        self._stages = stages or STAGES_CONFIG
        self._validate()

    def _validate(self):
        names = set()
        for stage in self._stages:
            if stage.name in names:
                raise ValueError(f"Duplicate stage name: {stage.name}")
            names.add(stage.name)
            for dep in stage.depends_on:
                if dep not in names and dep not in {s.name for s in self._stages}:
                    raise ValueError(
                        f"Stage '{stage.name}' depends on unknown stage '{dep}'"
                    )

    @property
    def stages(self) -> list[PipelineStage]:
        return sorted(self._stages, key=lambda s: s.order)

    @property
    def total_weight(self) -> float:
        return sum(s.weight for s in self.stages)

    @property
    def stage_names(self) -> list[str]:
        return [s.name for s in self.stages]

    def get_stage(self, name: str) -> Optional[PipelineStage]:
        for stage in self.stages:
            if stage.name == name:
                return stage
        return None

    def get_ordered_stages(self) -> list[PipelineStage]:
        return sorted(self._stages, key=lambda s: s.order)

    def get_execution_order(self) -> list[PipelineStage]:
        ordered = []
        visited = set()

        def resolve(stage_name: str):
            if stage_name in visited:
                return
            visited.add(stage_name)
            stage = self.get_stage(stage_name)
            if stage:
                for dep in stage.depends_on:
                    resolve(dep)
                ordered.append(stage)

        for stage in self.get_ordered_stages():
            resolve(stage.name)

        return ordered

    def get_next_pending_stage(
        self, stage_statuses: dict[str, StageStatus]
    ) -> Optional[PipelineStage]:
        for stage in self.get_execution_order():
            status = stage_statuses.get(stage.name, StageStatus.PENDING)
            if status == StageStatus.PENDING:
                deps_met = all(
                    stage_statuses.get(dep) == StageStatus.COMPLETED
                    for dep in stage.depends_on
                )
                if deps_met:
                    return stage
        return None

    def to_dict(self) -> list[dict]:
        return [
            {
                "name": s.name,
                "display_name": s.display_name,
                "description": s.description,
                "weight": s.weight,
                "order": s.order,
                "is_required": s.is_required,
                "depends_on": s.depends_on,
            }
            for s in self.stages
        ]
