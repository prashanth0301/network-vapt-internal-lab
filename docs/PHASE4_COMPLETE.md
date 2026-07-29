# Phase 4 — Assessment Engine Foundation ✅ Complete

---

## Deliverables

### Assessment Engine (9 files)

| File | Description |
|------|-------------|
| `services/assessment/__init__.py` | Package exports with singleton `assessment_manager` |
| `services/assessment/lifecycle.py` | `AssessmentStatus` and `StageStatus` enums with state machine validation (`can_transition_to`, `is_terminal`, `is_active`, `is_startable`) |
| `services/assessment/pipeline.py` | `PipelineStage` dataclass, `AssessmentPipeline` with dependency resolution, execution ordering, 3 pre-defined pipelines (full_assessment, host_discovery, port_scan) |
| `services/assessment/progress_tracker.py` | `ProgressTracker` with per-stage weight-based progress calculation, stage lifecycle tracking, stage error/summary capture |
| `services/assessment/stage_manager.py` | `StageManager` with pluggable handler registration, async stage execution, error handling, cancelled task support |
| `services/assessment/runner.py` | `AssessmentRunner` with `asyncio.create_task` background execution, cancellation via `asyncio.Event`, pipeline execution loop with dependency sequencing |
| `services/assessment/manager.py` | `AssessmentManager` — central orchestrator: CRUD for assessments, status transitions, progress retrieval, pipeline stage definitions (FULL_ASSESSMENT_STAGES with 6 stages, HOST_DISCOVERY_STAGES, PORT_SCAN_STAGES) |
| `services/assessment/exceptions.py` | 5 custom exceptions: `AssessmentException`, `AssessmentNotFoundError`, `AssessmentInvalidTransitionError`, `AssessmentAlreadyRunningError`, `AssessmentStageError`, `PipelineConfigurationError` |

### API Endpoints (2 files)

| File | Endpoints |
|------|-----------|
| `schemas/assessment.py` | `AssessmentCreate`, `AssessmentUpdate`, `StageInfo`, `StageProgress`, `AssessmentProgress`, `AssessmentResponse`, `AssessmentStatusResponse`, `PipelineResponse` |
| `api/v1/assessments.py` | `POST /api/v1/assessments` (create), `GET /api/v1/assessments` (list), `GET /api/v1/assessments/{id}` (detail + progress), `POST /api/v1/assessments/{id}/start` (start), `POST /api/v1/assessments/{id}/cancel` (cancel), `DELETE /api/v1/assessments/{id}` (delete), `GET /api/v1/assessments/pipelines/{scan_type}` (pipeline stages) |

### Router Update

| File | Change |
|------|--------|
| `api/v1/__init__.py` | Added `assessments_router` to `v1_router` |

### Tests (1 file, 20 test cases)

| Test Group | Tests |
|------------|-------|
| `TestAssessmentLifecycle` | 4 tests: status transitions, stage transitions, terminal status, active status |
| `TestAssessmentPipeline` | 6 tests: creation, total weight, execution order, duplicate error, unknown dependency, negative weight, next pending stage, dependency waiting |
| `TestProgressTracker` | 6 tests: initial state, progress increases, all complete, skipped stage, to_dict structure, stage error, stage summary |
| `TestAssessmentManager` | 10 tests: create, get, nonexistent raises, list, filter, update status, invalid transition, delete, delete nonexistent, progress retrieval, status retrieval, pipeline stages, singleton |

---

## Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| **Enum state machines** | Type-safe status management with explicit transition validation |
| **Weight-based progress** | Each stage has proportional weight (total = 100%); progress = completed weight / total |
| **Stage dependency resolution** | DAG-based execution order with topological sorting |
| **Pluggable stage handlers** | `StageManager.register_handler()` allows future phases to connect real tool execution |
| **asyncio background tasks** | Simple, no external dependencies; `asyncio.Event` for cancellation |
| **Design for queue migration** | `AssessmentRunner` is a thin abstraction — can swap to Celery/ARQ later |
| **Singleton manager** | In-memory for Phase 4; DB persistence will be added when services connect |
| **Pipeline presets** | `full_assessment` (6 stages), `host_discovery` (1 stage), `port_scan` (1 stage) |

---

## Pipeline Structure

```
Full Assessment Pipeline (100% total)

Stage 1: host_discovery  (10%)  ───→ Stage 2: port_scan (25%)  ───→ Stage 3: service_enum (15%)
                                                                          │
                                                                          ▼
Stage 6: report (10%)  ←─── Stage 5: cve_intel (10%)  ←─── Stage 4: vuln_scan (30%)
```

---

## Testing Instructions

```bash
cd backend
pytest tests/test_assessment_engine.py -v --asyncio-mode=auto

# Expected: 20 passed

# Run with coverage
pytest tests/test_assessment_engine.py -v --cov=app.services.assessment --cov-report=term
```

---

## API Usage Examples

```bash
# Create an assessment
curl -X POST http://localhost:8000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d '{"name":"Lab Scan","scan_type":"full_assessment","target":"192.168.56.0/24"}'

# List assessments
curl http://localhost:8000/api/v1/assessments

# Get assessment with progress
curl http://localhost:8000/api/v1/assessments/{id}

# Start assessment
curl -X POST http://localhost:8000/api/v1/assessments/{id}/start

# Cancel assessment
curl -X POST http://localhost:8000/api/v1/assessments/{id}/cancel

# Delete assessment
curl -X DELETE http://localhost:8000/api/v1/assessments/{id}

# Get pipeline stages
curl http://localhost:8000/api/v1/assessments/pipelines/full_assessment
```

---

## Next Phase

**Phase 5 — Dashboard Development**
- Connect dashboard to real assessment APIs
- Replace mock data with live assessment data
- Add real-time scan progress polling
- Implement assessment creation from UI
- Add interactive filtering and search
- Enhance charts with real data

---

## Suggested Git Commit

```
feat: complete Phase 4 — assessment engine foundation

- Implement AssessmentStatus/StageStatus state machines with validation
- Build AssessmentPipeline with DAG dependency resolution
- Create ProgressTracker with weight-based calculation
- Implement StageManager with pluggable handler registration
- Build AssessmentRunner with asyncio background tasks
- Create AssessmentManager orchestrator with CRUD + lifecycle
- Add 7 REST API endpoints (create, list, get, start, cancel, delete, pipeline)
- Define pipeline presets (full_assessment, host_discovery, port_scan)
- Write 20 unit tests across lifecycle, pipeline, tracker, manager
- Design for future queue migration (abstract runner interface)
```
