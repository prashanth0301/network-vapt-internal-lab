# Architecture

## System Overview

The Network VAPT Platform is a full-stack application with a clear three-tier architecture:

```
┌─────────────────────────────────────────────────┐
│                   Frontend                       │
│  React 18 · TypeScript · Vite · Tailwind CSS    │
│  20 pages · 18 services · 12 types modules      │
│  Port 5173                                      │
└──────────────────┬──────────────────────────────┘
                   │ HTTP (REST)
┌──────────────────▼──────────────────────────────┐
│                   Backend                        │
│  FastAPI · SQLAlchemy 2.0 (async) · Pydantic v2 │
│  94 endpoints · 16 routers · 23+ services       │
│  Port 8000                                      │
└──────────────────┬──────────────────────────────┘
                   │ asyncpg (connection pool)
┌──────────────────▼──────────────────────────────┐
│                Database                          │
│  PostgreSQL 16 · 17 tables · UUID PKs           │
│  Port 5432                                      │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│              Scanner Layer                       │
│  Nmap · OpenVAS · Metasploit (pluggable)        │
└─────────────────────────────────────────────────┘
```

---

## Backend Architecture

### Application Lifecycle

The FastAPI application follows a managed lifespan pattern:

```
Startup
  1. Validate configuration
  2. Initialize database (create tables)
  3. Bootstrap default admin user
  4. Seed default application settings
  5. Register 6 assessment stage handlers
  6. Start Uvicorn server

Shutdown
  1. Close database connection pool
```

### Directory Structure

```
backend/
├── app/
│   ├── main.py                    # App factory, lifespan, middleware
│   ├── core/
│   │   ├── config.py              # Pydantic Settings (env-based)
│   │   ├── database.py            # Async engine, session factory
│   │   ├── dependencies.py        # Shared FastAPI dependencies
│   │   └── logging.py             # Loguru configuration
│   ├── api/
│   │   ├── router.py              # Root API router
│   │   └── v1/
│   │       ├── __init__.py        # V1 router assembly (16 sub-routers)
│   │       ├── auth.py            # Auth + audit logs
│   │       ├── users_api.py       # User CRUD
│   │       ├── dashboard.py       # Dashboard summary
│   │       ├── assessments.py     # Assessment lifecycle
│   │       ├── hosts.py           # Host discovery
│   │       ├── ports.py           # Port scanning
│   │       ├── services.py        # Service intelligence
│   │       ├── vulnerabilities.py # Vulnerability scanning
│   │       ├── exploits.py        # Exploit verification
│   │       ├── cves.py            # CVE intelligence
│   │       ├── reports_api.py     # Report generation
│   │       ├── captures.py        # Packet capture
│   │       ├── artifacts.py       # Scan artifacts
│   │       ├── history.py         # History cleanup
│   │       ├── settings.py        # Application settings
│   │       └── health.py          # Health check
│   ├── models/                    # 17 SQLAlchemy models
│   ├── schemas/                   # Pydantic request/response schemas
│   └── services/                  # Business logic layer
│       ├── auth/                  # JWT, permissions, bootstrap
│       ├── scanner/               # Nmap, OpenVAS implementations
│       ├── exploit_provider/      # Metasploit integration
│       ├── cve_provider/          # NVD integration
│       ├── assessment/            # Pipeline engine, stage handlers
│       └── *.py                   # 23 domain service modules
├── tests/                         # 23 test files (647 tests)
├── alembic/                       # Database migrations
├── requirements.txt               # 16 direct dependencies
└── pyproject.toml                 # Build config, ruff, pytest
```

### Service Layer Pattern

Every domain follows a consistent service pattern:

```
API Router (validation, auth, HTTP concerns)
    ↓
Service Module (business logic, orchestration)
    ↓
SQLAlchemy Models (data access)
    ↓
PostgreSQL (persistence)
```

Key services:

| Service | Responsibility |
|---|---|
| `assessment/` | Pipeline engine, stage orchestration, lifecycle management |
| `auth/` | JWT creation/validation, password hashing, RBAC permissions |
| `scanner_manager.py` | Registry-based scanner abstraction |
| `exploit_manager.py` | Exploit provider orchestration |
| `dashboard_service.py` | Aggregation queries for dashboard widgets |
| `report_service.py` | Report generation (JSON, HTML, PDF) |
| `audit_log_service.py` | Audit trail querying and export |
| `risk_engine.py` | Weighted severity scoring |

---

## Data Model

### Entity Relationship Diagram

```
User
  └── AuditLog (user_id)

Scan (Assessment)
  ├── Host (scan_id)
  │   ├── Port (host_id)
  │   │   ├── Service (port_id)
  │   │   │   └── Vulnerability (service_id)
  │   │   │       └── CVE (vuln_id)
  │   │   │       └── Exploit (vulnerability_id)
  │   │   └── Vulnerability (port_id, host_id)
  │   └── Exploit (host_id)
  ├── Report (scan_id)
  ├── Artifact (assessment_id)
  └── PacketCapture (assessment_id)
      ├── Packet (capture_id)
      └── Conversation (capture_id)

Setting (key-value)
Log (application logs)
ExploitRun (exploit execution records)
```

### Core Tables

| Table | Primary Key | Key Columns | Purpose |
|---|---|---|---|
| `users` | UUID | username, email, role, status | User accounts and RBAC |
| `scans` | UUID | name, scan_type, target, status, started_at, completed_at | Assessment records |
| `hosts` | UUID | scan_id, ip_address, hostname, os_name, status | Discovered hosts |
| `ports` | UUID | host_id, port, protocol, state | Open/closed ports |
| `services` | UUID | port_id, name, product, version, normalized_name | Detected services |
| `vulnerabilities` | UUID | host_id, service_id, port_id, name, severity, cvss_score | Findings |
| `cves` | UUID | vuln_id, cve_id, cvss_score, exploit_available, kev_status | CVE intelligence |
| `exploits` | UUID | host_id, vulnerability_id, provider, module_name, status | Exploit records |
| `reports` | UUID | scan_id, title, report_type, format, filepath | Generated reports |
| `artifacts` | UUID | assessment_id, stage_name, scanner, status, path | Scan artifacts |
| `packet_captures` | UUID | assessment_id, interface, status | Capture sessions |
| `packets` | UUID | capture_id, protocol, source, destination | Individual packets |
| `conversations` | UUID | capture_id, src_ip, dst_ip, protocol | Network conversations |
| `audit_logs` | UUID | user_id, action, resource_type, details | Security audit trail |
| `settings` | UUID | key, value, category, setting_type | Application config |
| `logs` | UUID | level, module, message | Application logs |
| `exploit_runs` | UUID | exploit_id, status, output | Exploit execution history |

### UUID Primary Keys

All tables use UUID v4 primary keys (generated server-side) rather than auto-incrementing integers. This provides:

- Globally unique identifiers across distributed systems
- No sequential enumeration (security benefit)
- Safe for concurrent inserts

### Timestamps

Every table includes `created_at` and `updated_at` columns via the `TimestampMixin`, automatically managed by SQLAlchemy.

---

## Assessment Pipeline

The assessment pipeline is the core workflow engine. It orchestrates 6 sequential stages:

```
┌─────────────────┐
│  1. Host        │  Ping sweep to identify live hosts
│     Discovery   │  Service: host_discovery_service.py
└────────┬────────┘
         ▼
┌─────────────────┐
│  2. Port Scan   │  Nmap SYN scan for open ports
│                 │  Service: port_scan_service.py
└────────┬────────┘
         ▼
┌─────────────────┐
│  3. Service     │  Service detection, version ID, banners
│     Intelligence│  Service: service_intelligence_service.py
└────────┬────────┘
         ▼
┌─────────────────┐
│  4. Vuln        │  Nmap/OpenVAS vulnerability scanning
│     Assessment  │  Service: vulnerability_assessment_service.py
└────────┬────────┘
         ▼
┌─────────────────┐
│  5. CVE         │  NVD enrichment, EPSS, KEV lookup
│     Intelligence│  Service: cve_intelligence_handler.py
└────────┬────────┘
         ▼
┌─────────────────┐
│  6. Exploit     │  Metasploit module matching
│     Verification│  Service: exploit_verification_handler.py
└─────────────────┘
```

### Pipeline Registration

Stage handlers are registered at startup in `main.py`:

```python
assessment_manager.register_stage("host_discovery", host_discovery_handler)
assessment_manager.register_stage("port_scan", port_scan_handler)
assessment_manager.register_stage("service_intelligence", service_intelligence_handler)
assessment_manager.register_stage("vulnerability_assessment", vulnerability_assessment_handler)
assessment_manager.register_stage("cve_intelligence", cve_intelligence_handler)
assessment_manager.register_stage("exploit_verification", exploit_verification_handler)
```

### Progress Tracking

Each assessment stores:
- `progress_percent` — Overall completion percentage
- `progress` — Detailed per-stage progress with status and timestamps
- `pipeline` — Pipeline stage definitions with weights

---

## Scanner Integration

### Pluggable Architecture

The `ScannerManager` provides a registry-based abstraction:

```python
class ScannerManager:
    scanners: dict[str, VulnerabilityScanner]

    def register(self, name, scanner): ...
    def get_scanner(self, name): ...
    def run_scan(self, scanner_name, target, ports, scan_profile): ...
```

### Scanner Interface

All scanners implement the `VulnerabilityScanner` abstract base class:

```python
class VulnerabilityScanner(ABC):
    async def connect(self) -> bool
    async def disconnect(self)
    async def scan(self, target, ports, scan_profile) -> str
    async def cancel(self, scan_id) -> bool
    async def get_status(self, scan_id) -> ScannerStatus
    async def fetch_results(self, scan_id) -> ScanResult
```

### Registered Scanners

| Scanner | Module | Purpose |
|---|---|---|
| `nmap` | `scanner/nmap_vuln.py` | Nmap-based port and vulnerability scanning |
| `openvas` | `scanner/openvas.py` | OpenVAS vulnerability scanning |

### Scan Profiles

| Profile | Description |
|---|---|
| `quick` | Fast scan of common ports |
| `standard` | Full port range, default scripts |
| `deep` | Full port range, all scripts, version detection |
| `custom` | User-specified parameters |

---

## Security Architecture

### Authentication Flow

```
Client                    Backend                   Database
  │                          │                         │
  │  POST /auth/login        │                         │
  │  {username, password}    │                         │
  │ ───────────────────────> │                         │
  │                          │  SELECT user WHERE      │
  │                          │  username = ?           │
  │                          │ ───────────────────────> │
  │                          │ <─────────────────────── │
  │                          │  verify_password()      │
  │                          │  create_access_token()  │
  │                          │  create_refresh_token() │
  │  {access_token,          │                         │
  │   refresh_token}         │                         │
  │ <─────────────────────── │                         │
```

### JWT Token Structure

**Access Token:**
```json
{
  "sub": "user-uuid",
  "role": "administrator",
  "exp": 1785812813,
  "type": "access"
}
```

**Refresh Token:**
```json
{
  "sub": "user-uuid",
  "exp": 1786415813,
  "type": "refresh"
}
```

### Permission System

Three roles with hierarchical permissions:

```
administrator (9 permissions)
  ├── create:assessment
  ├── delete:assessment
  ├── view:reports
  ├── manage:users
  ├── manage:settings
  ├── run:scans
  ├── export:reports
  ├── manage:integrations
  └── view:audit

security_analyst (5 permissions)
  ├── create:assessment
  ├── view:reports
  ├── run:scans
  ├── export:reports
  └── view:audit

viewer (1 permission)
  └── view:reports
```

### Endpoint Protection

Routes are protected using FastAPI dependency injection:

```python
@router.get("/users")
async def list_users(
    current_user: User = Depends(require_permissions(["manage:users"]))
):
    ...
```

In addition to per-route permission checks, every router except `health` and the
auth endpoints enforces authentication at the router level via
`dependencies=[Depends(get_current_user)]`, so unauthenticated requests are
rejected with 401 before reaching any handler.

### Audit Logging

Every significant action is recorded in the `audit_logs` table:

```python
await auth_service.log_audit(
    session=session,
    user_id=user.id,
    action="user_created",
    resource_type="user",
    resource_id=new_user.id,
    details={"username": new_user.username},
    ip_address=request.client.host,
    user_agent=request.headers.get("user-agent"),
)
```

---

## Frontend Architecture

### Component Structure

```
src/
├── pages/              # 20 route-level components
├── components/
│   ├── layout/         # DashboardLayout, Header, Sidebar, Breadcrumbs, Toast
│   ├── ui/             # Badge, Button, Card, LoadingSpinner
│   ├── assessment/     # Shared assessment components (Stat, SeverityChips, etc.)
│   └── *.tsx           # Domain-specific modals (ExploitDetailModal, etc.)
├── services/           # 18 API service modules
├── types/              # 12 TypeScript type modules
├── context/            # AuthContext (React Context)
├── hooks/              # useTheme, useToast
├── utils/              # constants
└── router/             # React Router configuration
```

### State Management

The application uses a lightweight state management approach:

| Pattern | Used For |
|---|---|
| **React Context** | Authentication state (`AuthContext`) |
| **localStorage + CustomEvent** | Active assessment selection (`assessmentStore`) |
| **Component state** | Page-level data, filters, UI state |
| **URL params** | Host details, assessment overview |

The `assessmentStore` uses a publish-subscribe pattern via `localStorage` and `CustomEvent`:

```typescript
// Set active assessment
setActiveAssessment(id, name)
  → localStorage.setItem(...)
  → window.dispatchEvent(new CustomEvent('vapt-assessment-changed'))

// Listen for changes (in any component)
const tick = useAssessmentChangeTick()
  → useEffect(() => {
      window.addEventListener('vapt-assessment-changed', handler)
    })
```

### API Communication

All API calls go through a centralized Axios instance (`api.ts`):

- **Base URL:** Configured via `VITE_API_BASE_URL` (defaults to `/api/v1`)
- **Timeout:** 30 seconds
- **Auth:** Automatic `Bearer` token injection via request interceptor
- **Error handling:** 401 responses auto-redirect to login
- **Response shape:** All responses follow `{status, data, pagination?, message?, timestamp?}`

### Build Pipeline

```
TypeScript source
  → tsc (type checking)
  → Vite (bundling + minification)
  → dist/ (static files)
  → serve -s dist (production serving)
```

---

## Deployment Architecture

### Docker Compose

```yaml
services:
  db:        # PostgreSQL 16
  backend:   # FastAPI + Uvicorn
  frontend:  # Node.js + serve
  vulnapache: # Vulnerable Apache (lab target)
  ftp:        # FTP service (lab target)
```

### Container Communication

```
Browser → :5173 (frontend container)
            ↓ API calls
         :8000 (backend container)
            ↓ asyncpg
         :5432 (database container, internal network only)
```

### Volume Mounts

| Host Path | Container Path | Purpose |
|---|---|---|
| `frontend/` | `/app` | Live frontend code (dev) |
| `reports/` | `/app/reports` | Generated report files |
| `screenshots/` | `/app/screenshots` | Scanner screenshots |
| `wireshark/` | `/app/wireshark` | Packet captures |
| `backend/logs/` | `/app/logs` | Application logs |
| `postgres_data` | `/var/lib/postgresql/data` | Database persistence |

---

## Testing Strategy

### Backend Tests (647 tests)

| Test File | Coverage |
|---|---|
| `test_auth.py` | JWT, permissions, login/logout |
| `test_user_management.py` | CRUD, roles, last-admin protection |
| `test_dashboard.py` | Aggregation correctness, empty state |
| `test_assessment_engine.py` | Pipeline lifecycle, stage execution |
| `test_audit_logs.py` | Filtering, export, permissions |
| `test_host_discovery.py` | Discovery service logic |
| `test_vulnerability_assessment.py` | Vuln scanning logic |
| `test_cve_intelligence.py` | CVE enrichment |
| `test_exploit_verification.py` | Exploit matching |
| `test_report_management.py` | Report generation |
| `test_settings.py` | Settings CRUD |
| `test_pcap_parser.py` | PCAP parsing |
| *...and 11 more* | |

### Frontend Tests (10 tests)

| Test File | Coverage |
|---|---|
| `Dashboard.test.tsx` | Recent assessment links |
| `AuditLogs.test.tsx` | Table rendering, debounce, export, permissions |
| `AssessmentOverview.test.tsx` | Field rendering, severity, risk, reports, error state |

### Running Tests

```bash
# Backend (from backend/)
py -3.14 -m pytest tests/ -q

# Frontend (from frontend/)
npm run test

# Lint (from backend/)
ruff check app/
```

---

## Performance Considerations

| Area | Approach |
|---|---|
| **Database** | Async connection pool (asyncpg), indexed foreign keys, UUID PKs |
| **API** | Paginated responses, optional field selection |
| **Frontend** | Debounced search (350ms), lazy component loading, code splitting |
| **Scanning** | Background task execution, progress polling |
| **Reports** | File-based storage, streamed downloads |

---

## Scalability Notes

The current architecture is designed for single-instance internal lab use. For multi-user production deployment, consider:

- **Horizontal scaling:** Multiple backend instances behind a load balancer
- **Database:** Read replicas for dashboard queries
- **Queue:** Redis/RabbitMQ for scan task distribution
- **Cache:** Redis for dashboard aggregation caching
- **Storage:** S3-compatible object storage for reports and captures
