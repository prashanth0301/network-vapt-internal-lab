# Network VAPT Platform v1.0

**Internal Network Vulnerability Assessment & Penetration Testing Platform**

A full-stack application for automating network security assessments — from host discovery through exploit verification — with an enterprise-grade dashboard, RBAC, and audit logging.

---

## Features

| Capability | Description |
|---|---|
| **6-Stage Assessment Pipeline** | Host Discovery → Port Scan → Service Intelligence → Vulnerability Assessment → CVE Intelligence → Exploit Verification |
| **Real-Time Dashboard** | Risk score, severity distribution, vulnerability trends, top ports, service distribution, top vulnerable hosts, activity timeline |
| **Assessment Selector** | Filter all dashboard widgets by individual assessment |
| **Scanner Integration** | Pluggable Nmap and OpenVAS backends via `ScannerManager` |
| **Exploit Verification** | Metasploit module matching, exploit execution, session tracking |
| **CVE Intelligence** | NVD enrichment, EPSS scoring, KEV status, vendor/product mapping |
| **Report Generation** | Executive, Technical, and Compliance reports in JSON, HTML, and PDF |
| **Packet Capture** | Live capture, PCAP upload, protocol analysis, conversation tracking |
| **User Management** | RBAC with 3 roles (Administrator, Security Analyst, Viewer) and 9 granular permissions |
| **Audit Logging** | Full audit trail with CSV/JSON export |
| **Role-Based Access Control** | Administrator, Security Analyst, Viewer with permission-gated endpoints |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11+ · FastAPI · SQLAlchemy 2.0 (async) · Pydantic v2 |
| **Database** | PostgreSQL 16 · asyncpg · Alembic migrations |
| **Frontend** | React 18 · TypeScript · Vite · Tailwind CSS · Recharts |
| **Auth** | JWT (HS256) · bcrypt · role-based permissions |
| **Scanning** | Nmap · OpenVAS (pluggable via abstract `VulnerabilityScanner` interface) |
| **Reporting** | Jinja2 templates · Markdown · ReportLab (PDF) |
| **Deployment** | Docker Compose (backend, frontend, PostgreSQL) |
| **Testing** | pytest (async) · vitest · @testing-library/react |

---

## Quick Start

```bash
# 1. Clone the repository
git clone <repository-url>
cd Network-VAPT-Internal-Lab

# 2. Copy environment file
cp .env.example .env

# 3. Start everything
cd docker
docker compose --env-file ..\.env up -d --build

# 4. Open the application
#    Frontend:  http://localhost:5173
#    Backend:   http://localhost:8000
#    API Docs:  http://localhost:8000/docs
```

**Default credentials:** `admin` / `Admin@123`

For detailed setup instructions, see [INSTALLATION.md](INSTALLATION.md).

---

## Project Structure

```
Network-VAPT-Internal-Lab/
├── backend/                    # FastAPI backend
│   ├── app/
│   │   ├── api/v1/            # 94 REST endpoints across 16 routers
│   │   ├── core/              # Config, database, dependencies
│   │   ├── models/            # 17 SQLAlchemy models
│   │   ├── schemas/           # Pydantic request/response schemas
│   │   └── services/          # 23+ service modules + scanner/exploit providers
│   ├── tests/                 # 23 test files (643 tests)
│   └── requirements.txt
├── frontend/                   # React SPA
│   ├── src/
│   │   ├── pages/             # 20 page components
│   │   ├── services/          # 18 API service modules
│   │   ├── components/        # Shared UI components
│   │   ├── types/             # TypeScript interfaces
│   │   └── context/           # Auth context
│   └── package.json
├── docker/                     # Docker Compose + Dockerfiles
├── scripts/                    # Utility scripts
├── reports/                    # Generated report files
├── screenshots/                # Scanner screenshots
├── wireshark/                  # Packet captures
└── .env.example               # Environment template
```

---

## Documentation

| Document | Description |
|---|---|
| [INSTALLATION.md](INSTALLATION.md) | System requirements, setup, Docker deployment, configuration |
| [USER_GUIDE.md](USER_GUIDE.md) | Feature walkthrough, navigation, workflows |
| [API_DOCUMENTATION.md](API_DOCUMENTATION.md) | Complete REST API reference (94 endpoints) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, data model, service layer, security |

---

## Default Accounts

| Role | Username | Password | Permissions |
|---|---|---|---|
| Administrator | `admin` | `Admin@123` | Full access (9 permissions) |
| Security Analyst | *(created via UI)* | *(set on creation)* | Scan, view reports, export, audit |
| Viewer | *(created via UI)* | *(set on creation)* | View reports only |

---

## License

MIT License — Copyright (c) 2026 Network VAPT Platform prashanth0301

See [LICENSE](../LICENSE) for details.
