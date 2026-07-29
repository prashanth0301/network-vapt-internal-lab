# Phase 2 — Backend Foundation ✅ Complete

---

## Deliverables

### Core Modules (6 files)

| File | Description |
|------|-------------|
| `app/core/config.py` | Pydantic Settings with environment variables, validation (DATABASE_URL assembly, LOG_LEVEL enum, CORS_ORIGINS parsing) |
| `app/core/database.py` | SQLAlchemy 2.0 async engine with `async_sessionmaker`, `get_db` generator, `init_db`/`close_db` lifecycle |
| `app/core/logging.py` | Structured logging with Loguru, JSON formatter, file rotation, interception of Python logging |
| `app/core/exceptions.py` | Custom exception hierarchy: `VAPTException` → `NotFoundException`, `ValidationException`, `ScanException`, `ToolException`, `DatabaseException` |
| `app/core/dependencies.py` | Dependency injection for async database sessions |
| `app/core/__init__.py` | Package init |

### ORM Models (12 tables, 13 files)

| File | Table | Key Columns |
|------|-------|-------------|
| `models/base.py` | — | `Base`, `UUIDMixin`, `TimestampMixin` |
| `models/host.py` | `hosts` | ip, mac, os, status, is_alive |
| `models/port.py` | `ports` | host FK, port, protocol, state |
| `models/service.py` | `services` | port FK, name, version, banner |
| `models/scan.py` | `scans` | type, target, status, parameters (JSONB) |
| `models/vulnerability.py` | `vulnerabilities` | host FK, severity, cvss, cve_ids (ARRAY) |
| `models/cve.py` | `cves` | vuln FK, cve_id, cvss, msf_module |
| `models/exploit.py` | `exploits` | cve FK, host FK, module_name |
| `models/exploit_run.py` | `exploit_runs` | exploit FK, host FK, session_id |
| `models/packet_capture.py` | `packet_captures` | filename, protocol_stats (JSONB) |
| `models/report.py` | `reports` | scan FK, format, filepath |
| `models/log.py` | `logs` | level, module, message, details (JSONB) |
| `models/setting.py` | `settings` | key (unique), value, category |
| `models/__init__.py` | — | All-model re-export |

### Pydantic Schemas (5 files)

| File | Schemas |
|------|---------|
| `schemas/common.py` | `SuccessResponse`, `ErrorResponse`, `PaginatedResponse`, `PaginationParams`, `PaginationMeta` |
| `schemas/health.py` | `HealthResponse` |
| `schemas/host.py` | `HostBase`, `HostCreate`, `HostUpdate`, `HostResponse`, `HostDiscoverRequest` |
| `schemas/scan.py` | `ScanBase`, `ScanCreate`, `ScanResponse` |

### API Routers (3 files)

| File | Description |
|------|-------------|
| `api/router.py` | Root router aggregator with `/api/v1` prefix |
| `api/v1/__init__.py` | V1 router with health endpoint mounted |
| `api/v1/health.py` | `GET /api/v1/health` — returns app version, DB status, uptime, service status |

### Middleware (2 files)

| File | Description |
|------|-------------|
| `middleware/cors.py` | CORS middleware with configurable origins from settings |
| `middleware/error_handler.py` | Global exception handlers for `VAPTException`, `RequestValidationError`, `SQLAlchemyError`, and generic `Exception` |

### Main Application (1 file)

| File | Description |
|------|-------------|
| `app/main.py` | FastAPI app with lifespan events (init/close DB), config validation on startup, custom Swagger/OpenAPI docs |

### Alembic (4 files)

| File | Description |
|------|-------------|
| `alembic.ini` | Alembic configuration |
| `alembic/env.py` | Async Alembic environment with SQLAlchemy async engine |
| `alembic/script.py.mako` | Migration template |
| `alembic/versions/001_initial_schema.py` | Initial migration: creates all 12 tables with indexes, constraints, FKs |

### Docker (3 files)

| File | Description |
|------|-------------|
| `docker/backend.Dockerfile` | Python 3.11-slim, pip install, uvicorn CMD |
| `docker/docker-compose.yml` | PostgreSQL 16 + backend services, volumes, health checks |
| `backend/.dockerignore` | Python cache, env, git exclusions |

### Testing (2 files)

| File | Description |
|------|-------------|
| `tests/conftest.py` | Async pytest fixtures: `setup_database`, `db_session`, `client` with dependency overrides |
| `tests/test_health.py` | 5 test cases: 200 status, response structure, valid status, app name, services dict |

### Configuration (4 files)

| File | Description |
|------|-------------|
| `.env.example` | All environment variables documented |
| `backend/pyproject.toml` | Ruff, isort, black, pytest settings |
| `backend/.pre-commit-config.yaml` | Pre-commit hooks: black, ruff, isort, mypy, trailing whitespace, YAML/JSON validation |
| `requirements.txt` | Updated in Phase 0 with all dependencies |

---

## Key Architecture Decisions

| Decision | Implementation |
|----------|---------------|
| Async everywhere | `asyncpg` driver, `AsyncSession`, `async_sessionmaker`, async lifespan |
| UUID PKs | `uuid.uuid4` with PostgreSQL `UUID` type across all tables |
| JSONB for flexible data | `parameters`, `summary`, `protocol_stats`, `details` columns |
| Structured logging | Loguru with JSON output + file rotation |
| Custom exception hierarchy | 5 exception types mapped to HTTP status codes |
| Config validation on startup | `validate_configuration()` runs in lifespan before DB init |
| Dependency injection | `get_db()` generator yields `AsyncSession` with commit/rollback |
| API versioning | `/api/v1/` prefix via router aggregation |

---

## Testing Instructions

```bash
cd backend
# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt

# Ensure PostgreSQL is running with database 'vapt_test'
# Run tests
pytest tests/ -v --asyncio-mode=auto

# Run with coverage
pytest tests/ -v --cov=app --cov-report=term
```

## Run Backend

```bash
# Ensure PostgreSQL is running with database 'vapt_db'
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# Swagger UI: http://localhost:8000/docs
# Health Check: http://localhost:8000/api/v1/health
```

## Docker Setup

```bash
docker-compose -f docker/docker-compose.yml up -d
docker-compose -f docker/docker-compose.yml logs -f backend
```

---

## Next Phase

**Phase 3 — Frontend Foundation**
- Initialize React + TypeScript + Tailwind CSS project
- Configure React Router
- Create layout components (Sidebar, Header, Main)
- Set up Axios API client
- Create type definitions
- Implement dark theme
- Connect to backend health endpoint
- Create placeholder pages for all modules

---

## Suggested Git Commit

```
feat: complete Phase 2 — backend foundation

- Implement FastAPI application with async lifespan
- Create SQLAlchemy 2.0 async models (12 tables)
- Configure Pydantic Settings with env validation
- Set up structured logging (Loguru, JSON, rotation)
- Build custom exception hierarchy with global handlers
- Implement CORS middleware and error handling
- Create Pydantic schemas with validation
- Configure Alembic with initial migration (12 tables)
- Add Docker support (Dockerfile + docker-compose)
- Write unit tests for health endpoint
- Set up pre-commit with black/ruff/isort/mypy
```
