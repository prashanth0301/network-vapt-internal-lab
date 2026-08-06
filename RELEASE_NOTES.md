# Release Notes — Network VAPT Platform v1.0.0

**Version:** 1.0.0 (Initial Release)
**Release Date:** August 2026
**License:** MIT

---

## Overview

The **Network VAPT Platform** is a full-stack application that automates internal network
Vulnerability Assessment and Penetration Testing (VAPT). From a single web console, security
teams can discover live hosts, enumerate ports and services, assess vulnerabilities, enrich
findings with CVE intelligence, verify exploits, capture and analyze network traffic, and
produce professional executive, technical, and compliance reports — all with role-based
access control and a complete audit trail.

The platform is built around a **6-stage assessment pipeline** (Host Discovery → Port Scan →
Service Intelligence → Vulnerability Assessment → CVE Intelligence → Exploit Verification) and
is deployed with Docker Compose for a fast, reproducible lab setup.

**Highlights at a glance:**

| Metric | Value |
|---|---|
| REST API endpoints | 95 |
| API routers | 16 |
| Database tables | 17 (all UUID primary keys) |
| Service modules | 23+ (plus scanner/exploit/CVE providers) |
| Frontend pages | 20 |
| Backend tests | 651 |
| User roles | 3 (Administrator, Security Analyst, Viewer) |
| Granular permissions | 9 |

---

## Features

| Capability | Description |
|---|---|
| **6-Stage Assessment Pipeline** | Host Discovery → Port Scan → Service Intelligence → Vulnerability Assessment → CVE Intelligence → Exploit Verification |
| **Real-Time Dashboard** | Risk score, severity distribution, vulnerability trends, top ports, service distribution, top vulnerable hosts, activity timeline |
| **Assessment Selector** | Filter all dashboard widgets by a single active assessment |
| **Scanner Integration** | Pluggable Nmap and OpenVAS backends via `ScannerManager` |
| **Exploit Verification** | Metasploit module matching, exploit execution, and session tracking |
| **CVE Intelligence** | NVD enrichment, EPSS scoring, KEV status, vendor/product mapping |
| **Report Generation** | Executive, Technical, and Compliance reports in JSON, HTML, and PDF |
| **Packet Capture** | Live capture, PCAP upload, protocol analysis, conversation tracking |
| **Global Search** | Expanded search across reports, services, hosts, assessment history, and audit logs |
| **User Management** | RBAC with 3 roles and 9 granular permissions |
| **Audit Logging** | Full audit trail with CSV/JSON export |
| **Health & Diagnostics** | `/health` endpoint and structured application logging |

---

## Architecture

The platform uses a clean three-tier architecture:

```
+---------------------------------------------------+
|                    Frontend                        |
|  React 18 · TypeScript · Vite · Tailwind CSS      |
|  20 pages · 18 services · 12 type modules         |
|  Port 5173                                         |
+-------------------------+-------------------------+
                          | HTTP (REST)
+-------------------------v-------------------------+
|                     Backend                         |
|  FastAPI · SQLAlchemy 2.0 (async) · Pydantic v2   |
|  94 endpoints · 16 routers · 23+ services         |
|  Port 8000                                          |
+-------------------------+-------------------------+
                          | asyncpg (connection pool)
+-------------------------v-------------------------+
|                   Database                          |
|  PostgreSQL 16 · 17 tables · UUID PKs             |
|  Port 5432 (internal network only)                 |
+-------------------------+-------------------------+
                          |
+-------------------------v-------------------------+
|                 Scanner Layer                       |
|  Nmap · OpenVAS · Metasploit (pluggable)          |
+---------------------------------------------------+
```

**Design principles:**

- **Layered service pattern** — API routers handle validation and auth; service modules hold
  business logic; SQLAlchemy models provide data access; PostgreSQL persists state.
- **Pluggable scanners** — the `VulnerabilityScanner` abstract interface lets scanners
  (Nmap, OpenVAS) be registered, swapped, or extended without touching the pipeline.
- **Pipeline engine** — the assessment manager registers six stage handlers at startup and
  tracks per-stage progress, timestamps, and overall completion percentage.
- **UUID primary keys** — all tables use server-generated UUID v4 keys (no sequential
  enumeration, safe for concurrent inserts).
- **Background scanning** — long-running scan stages execute as background tasks with
  client-side progress polling.

---

## Technology Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11+ · FastAPI · SQLAlchemy 2.0 (async) · Pydantic v2 · Loguru |
| **Database** | PostgreSQL 16 · asyncpg · Alembic migrations |
| **Frontend** | React 18 · TypeScript · Vite · Tailwind CSS · Recharts |
| **Authentication** | JWT (HS256, access + refresh) · bcrypt · role-based permissions |
| **Scanning** | Nmap · OpenVAS (pluggable via `VulnerabilityScanner` interface) |
| **Exploitation** | Metasploit RPC (`msfrpcd`) |
| **CVE Intelligence** | NVD API · EPSS scoring · KEV catalog |
| **Packet Capture** | dumpcap / tshark (Wireshark) · Npcap · scapy · psutil |
| **Reporting** | Jinja2 templates · Markdown · ReportLab (PDF) |
| **Deployment** | Docker Compose (backend, frontend, PostgreSQL, lab targets) |
| **Testing** | pytest (async) · vitest · @testing-library/react · ruff |

---

## Modules

| Module | Description |
|---|---|
| **Authentication & Users** | Login/logout, JWT access + refresh tokens, user CRUD, role management, last-administrator protection, password reset |
| **Assessments** | Assessment lifecycle (create, run, view, delete) with a selectable active assessment |
| **Host Discovery** | Ping sweeps that identify live hosts with OS fingerprinting and MAC/vendor data |
| **Port Scanning** | Nmap SYN scans (quick/standard/deep/custom profiles) with open/closed state |
| **Service Intelligence** | Service detection, version identification, and banner capture |
| **Vulnerability Assessment** | Nmap and OpenVAS vulnerability scanning with CVSS scoring |
| **CVE Intelligence** | NVD enrichment, EPSS score, KEV status, vendor/product mapping |
| **Exploit Verification** | Metasploit module matching and execution with session tracking |
| **Reports** | Executive, Technical, and Compliance reports in JSON, HTML, and PDF |
| **Packet Analysis** | Live capture, PCAP upload, search, delete (admin), protocol distribution, conversations, packet list |
| **Dashboard** | Aggregated analytics and risk scoring across assessments |
| **Assessment History** | Searchable, filterable history of all assessments |
| **Settings** | Application-wide settings (organization, theme, scanner, security options) |
| **Audit Logs** | Complete audit trail with CSV/JSON export |
| **Artifacts** | Per-stage scanner artifacts and results |

---

## Security Features

- **Role-Based Access Control (RBAC)** — three roles with hierarchical permissions:

  - `administrator` — 9 permissions (full access)
  - `security_analyst` — 5 permissions (scan, view/export reports, view audit)
  - `viewer` — 1 permission (view reports only)

- **Permission-gated endpoints** — every route is protected via FastAPI dependency injection
  (`require_permissions([...])`).
- **JWT authentication** — short-lived access tokens with role claims and rotating refresh
  tokens; 401 responses redirect to login.
- **Secure password handling** — bcrypt password hashing, minimum-length validation, and
  last-administrator protection on role/status changes.
- **Audit logging** — every significant action (login, logout, user management, settings
  changes) is recorded with actor, action, resource, IP address, user agent, and details.
- **UUID identifiers** — non-enumerable resource IDs across all tables.
- **Validation** — Pydantic v2 request/response validation and input sanitization.
- **Login throttling** — rate limiting on the login endpoint.
- **Containerized exposure** — the database port is exposed on the internal Docker network
  only; only the frontend (5173) and backend (8000) are published.

---

## Dashboard

The dashboard provides real-time visibility into assessment results and network posture:

- **Overall risk score** and weighted severity metrics
- **Severity distribution** (critical / high / medium / low) across findings
- **Vulnerability trends** over time
- **Top ports** and **service distribution** charts
- **Top vulnerable hosts** leaderboard
- **Recent activity timeline**
- **Assessment selector** to scope every widget to the active assessment

All aggregation queries run against PostgreSQL through a dedicated dashboard service and
reflect the currently selected assessment.

---

## Assessment Workflow

1. **Create an assessment** — name, target network, and scan type (Nmap/OpenVAS) are
   captured; a scan profile (quick, standard, deep, custom) is selected.
2. **Pipeline execution** — the six stages run sequentially, each registering progress,
   status, and timestamps:

   ```
   Host Discovery → Port Scan → Service Intelligence
   → Vulnerability Assessment → CVE Intelligence → Exploit Verification
   ```

3. **Progress tracking** — overall `progress_percent` plus per-stage status are polled by
   the frontend and surfaced in the UI.
4. **History** — completed assessments are stored in the assessment history module with
   full metadata (target, type, status, timing, duration, progress, risk level) and are
   searchable across all record fields.

---

## Packet Analysis

- **Interface detection** — the backend enumerates capture interfaces via `dumpcap -D` /
  `tshark -D`, enriched with IP address, MAC address, and Up/Down status using scapy and
  psutil. When no capture tool is present, a system-level fallback enumeration is used so
  the interface dropdown is never empty.
- **Live capture** — start/stop live captures on the selected interface (defaults to the
  Npcap loopback adapter when available).
- **Upload analysis** — upload `.pcap` / `.pcapng` / `.cap` files for offline analysis.
- **Search** — search captures by filename, protocol, date, packet count, and file size
  with case-insensitive matching (ILIKE).
- **Delete** — administrators can delete captures, which cascades to remove all associated
  packets, conversations, and the PCAP file from disk.
- **Protocol distribution** — per-capture breakdown of protocols with packet counts.
- **Conversations** — source/destination pairs with packet and byte totals.
- **Packet list** — timestamped, paginated packet viewer with protocol badges and
  filtering.
- **Friendly interface labels** — e.g., `Wi-Fi (192.168.188.129)`, `Ethernet`,
  `VMware VMnet8 (192.168.56.1)`.

---

## Reports

- **Three report types** — Executive, Technical, and Compliance.
- **Three output formats** — JSON, HTML, and PDF (generated with ReportLab).
- **Expanded search** — reports can be searched by title, filename, report type, format,
  scan ID, scan name/target/type/status, generator, and creation/update dates (including
  month and year keywords).
- **File-based storage** — generated reports are written to the mounted `reports/` volume
  and streamed for download.

---

## Audit Logs

- **Complete trail** — records every significant action with actor username, action,
  resource type and ID, IP address, user agent, status, and details.
- **Filters** — user, action, status (success/failure), and date range.
- **Sorting & pagination** — sort by timestamp, action, or username; page through results.
- **Export** — download filtered results as CSV (UTF-8 BOM) or JSON.
- **Role-gated** — Administrator and Security Analyst have read/export access; Viewer has
  no access.
- **Expanded search** — matches across username, user role, email, action, resource,
  resource type, resource ID, status, IP address, user agent, session ID, details JSON,
  timestamp, date, and time.

---

## Search Enhancements

v1.0 ships a **global search** capability across every major module. Each search is
server-side, case-insensitive, paginated, and respects the module's existing filters and
sorting:

| Module | Searchable Fields |
|---|---|
| **Assessment History** | Name, ID, target, scan type, status, timestamps, parameters/summary (incl. risk level), hostnames, progress, duration, "today" |
| **Hosts** | IP address, hostname, OS name/version/accuracy, vendor, MAC address, status, latency, scan ID, scan name, open-port/service counts, service name/product/version |
| **Services** | Name, product, version, normalized names, banner, extra info, protocol, port (and `port/protocol`), host IP/hostname/OS, vendor, state |
| **Reports** | Title, filename, report type, format, scan ID, scan name/target/type/status, generator, created/updated dates (incl. month/year) |
| **Audit Logs** | Username, role, email, action, resource, resource type, resource ID, status, IP address, user agent, session ID, details, timestamp, date, time |
| **Packet Analysis** | Network interface enumeration (friendly name, description, IP, MAC, Up/Down status) |

Search terms such as `192.168.188.130`, `Ubuntu`, `apache`, `80/tcp`, `completed`,
`2026`, `August`, `administrator`, and `success` demonstrate cross-field matching against
real lab data.

---

## Screenshots

> Screenshots are placeholders. Replace the paths with the actual capture files before
> publishing this release.

| Section | Screenshot |
|---|---|
| Login | ![Login](screenshots/login.png) |
| Dashboard | ![Dashboard](screenshots/dashboard.png) |
| Assessment Workflow | ![Assessment Workflow](screenshots/assessment-workflow.png) |
| Assessment History | ![Assessment History](screenshots/assessment-history.png) |
| Hosts | ![Hosts](screenshots/hosts.png) |
| Services | ![Services](screenshots/services.png) |
| Vulnerabilities | ![Vulnerabilities](screenshots/vulnerabilities.png) |
| Exploit Verification | ![Exploit Verification](screenshots/exploits.png) |
| Packet Analysis | ![Packet Analysis](screenshots/packet-analysis.png) |
| Reports | ![Reports](screenshots/reports.png) |
| Audit Logs | ![Audit Logs](screenshots/audit-logs.png) |
| User Management | ![User Management](screenshots/user-management.png) |
| Settings | ![Settings](screenshots/settings.png) |

---

## Installation

### System Requirements

| Component | Requirement |
|---|---|
| CPU | 4 cores |
| RAM | 8 GB |
| Disk | 20 GB free |
| Network | Adapter with access to target networks |

### Prerequisites

| Software | Version |
|---|---|
| Docker | 24.0+ |
| Docker Compose | v2.20+ |
| Git | 2.30+ |
| Python (local dev only) | 3.11+ |
| Node.js (local dev only) | 20+ |

### Docker Deployment (Recommended)

```bash
# 1. Clone the repository
git clone <repository-url>
cd Network-VAPT-Internal-Lab

# 2. Copy the environment file and set secrets
cp .env.example .env
#  - Required: POSTGRES_PASSWORD, JWT_SECRET (change for production)

# 3. Build and start all services
cd docker
docker compose --env-file ..\.env up -d --build

# 4. Verify
docker ps --filter "name=vapt"
curl http://localhost:8000/api/v1/health

# 5. Open the application
#    Frontend:  http://localhost:5173
#    Backend:   http://localhost:8000
#    API Docs:  http://localhost:8000/docs
```

**Default credentials:** `admin` / `Admin@123`

> **Important:** Change the default admin password immediately in any shared or
> production environment.

### Containers

| Container | Port | Purpose |
|---|---|---|
| `vapt-db` | 5432 | PostgreSQL 16 database (internal only) |
| `vapt-backend` | 8000 | FastAPI backend |
| `vapt-frontend` | 5173 | React SPA (served by `serve`) |
| `vapt-vulnapache` | — | Vulnerable Apache target for lab testing |
| `vapt-ftp` | — | FTP service for lab testing |

### Local Development

```bash
# Backend
cd backend
python -m venv venv && venv\Scripts\activate   # or source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Frontend
cd frontend
npm install
npm run dev        # http://localhost:5173 (proxies /api to :8000)
```

On first startup the backend automatically creates all tables, seeds default settings, and
bootstraps the default administrator when the `users` table is empty. For production,
Alembic migrations are available (`alembic upgrade head`).

---

## Known Limitations

- **Single-instance design** — built for internal lab use; there is no horizontal
  scaling, message queue, or distributed scan-agent support yet.
- **Live packet capture** — requires Npcap and a capture tool (dumpcap/tshark from
  Wireshark) on the server. When the backend runs inside Docker, only container interfaces
  can be enumerated; host adapters are visible when the backend runs natively on the
  capture host.
- **External integrations** — CVE enrichment (NVD), exploit execution (Metasploit RPC),
  and OpenVAS scans depend on optional external services; these features are disabled
  gracefully when the services are unavailable.
- **Search result counts depend on data** — terms such as `failed` (status) or `logout`
  return zero results until matching records exist in the database.
- **Single scan worker** — scans execute as background tasks in a single Uvicorn worker;
  only one scan pipeline runs at a time by design.
- **No email/MFA/SSO** — notifications, multi-factor authentication, and SAML/OIDC
  single sign-on are not included in v1.0.
- **Default credentials** — the bootstrap admin (`admin` / `Admin@123`) must be changed
  before use in any non-isolated environment.
- **Windows-centric capture tooling** — capture tool discovery targets Npcap/Wireshark
  installation paths; other platforms require the tools on `PATH`.

---

## Future Roadmap

### v1.1 (Next Minor Release)

- **Scheduled & recurring scans** — cron-style scan scheduling with email digests
- **Vulnerability lifecycle** — findings state management (open/accepted/false-positive),
  comments, and assignees
- **Report scheduling & customization** — schedule report generation and add custom
  template editor with branding
- **Delta & comparison** — compare two assessments to highlight new/fixed vulnerabilities
- **Bulk operations** — CSV import/export of users and findings
- **SMTP notifications** — scan completion, new critical findings, and report delivery
- **Enhanced authentication** — MFA (TOTP) and optional SSO integration
- **MITRE ATT&CK mapping** — map findings to ATT&CK techniques

### v2.0 (Next Major Release)

- **Multi-tenant & multi-organization** support with isolated data spaces
- **Distributed scanning** — dedicated scan agents on remote networks with a Redis/Celery
  task queue and retry/failure handling
- **Horizontal scaling** — load-balanced backend instances and database read replicas
- **Object storage** — S3-compatible storage for reports, captures, and artifacts
- **Programmatic access** — API tokens and an expanded public API with webhooks
- **Compliance frameworks** — NIST CSF, ISO 27001, PCI-DSS, and SOC 2 report templates
- **Real-time dashboards** — WebSocket-driven live telemetry and scan progress
- **Advanced threat intelligence** — third-party TI feeds, IOC correlation, and
  threat-hunting queries

---

## Support

- **Documentation:** `docs/INSTALLATION.md`, `docs/USER_GUIDE.md`,
  `docs/API_DOCUMENTATION.md`, `docs/ARCHITECTURE.md`
- **Issues:** Report bugs and feature requests via the repository issue tracker.

**License:** MIT — Copyright (c) 2026 Network VAPT Platform prashanth0301
