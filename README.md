# Network VAPT Platform

> **Internal Network Vulnerability Assessment & Penetration Testing Platform**

A full-stack cybersecurity web application that orchestrates the complete internal network penetration testing lifecycle. Integrates Nmap, Nessus/OpenVAS, Metasploit Framework, and Wireshark into a unified dashboard with professional report generation.

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18+-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5+-3178C6?logo=typescript)](https://www.typescriptlang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-4169E1?logo=postgresql)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker)](https://docker.com)
[![VirtualBox](https://img.shields.io/badge/VirtualBox-7+-183A61?logo=virtualbox)](https://virtualbox.org)

---

## Architecture

```
┌──────────┐    ┌──────────┐    ┌────────────┐    ┌──────────────┐
│  React   │───>│  FastAPI │───>│ Assessment │───>│  PostgreSQL  │
│ Dashboard│    │  Backend │    │   Engine   │    │  Database    │
└──────────┘    └──────────┘    └─────┬──────┘    └──────────────┘
                                      │
                        ┌─────────────┼─────────────┐
                        ▼             ▼             ▼
                      Nmap       Nessus/OpenVAS  Metasploit
                                      │
                                ┌─────▼─────┐
                                │  Wireshark │
                                │  (TShark)  │
                                └───────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Tailwind CSS 3, Vite 5, Recharts, React Router v6, Axios |
| Backend | FastAPI 0.115+, Python 3.11+, SQLAlchemy 2.0 Async, Pydantic v2, Loguru |
| Database | PostgreSQL 16, Alembic migrations |
| Security Tools | Nmap 7.94+, OpenVAS/Nessus, Metasploit 6.x, TShark 4.x |
| Virtualization | VirtualBox 7+ / VMware Workstation Pro |
| Containerization | Docker, Docker Compose |
| CI/CD | GitHub Actions |
| Code Quality | Black, Ruff, isort, mypy, pre-commit |

---

## Backend Architecture

```
backend/
├── app/
│   ├── api/                 # REST API layer
│   │   ├── router.py        # Root router aggregator
│   │   └── v1/              # API v1 endpoints
│   │       ├── __init__.py  # V1 router mounting
│   │       └── health.py    # Health check endpoint
│   ├── core/                # Application core
│   │   ├── config.py        # Pydantic Settings (env validation)
│   │   ├── database.py      # SQLAlchemy async engine + session
│   │   ├── dependencies.py  # Dependency injection
│   │   ├── exceptions.py    # Custom exception hierarchy
│   │   └── logging.py       # Structured logging (Loguru)
│   ├── middleware/           # FastAPI middleware
│   │   ├── cors.py          # CORS configuration
│   │   └── error_handler.py # Global exception handlers
│   ├── models/              # SQLAlchemy ORM models (12 tables)
│   │   ├── base.py          # Declarative Base + Mixins
│   │   ├── host.py          # hosts table
│   │   ├── port.py          # ports table
│   │   ├── service.py       # services table
│   │   ├── scan.py          # scans table
│   │   ├── vulnerability.py # vulnerabilities table
│   │   ├── cve.py           # cves table
│   │   ├── exploit.py       # exploits table
│   │   ├── exploit_run.py   # exploit_runs table
│   │   ├── packet_capture.py# packet_captures table
│   │   ├── report.py        # reports table
│   │   ├── log.py           # logs table
│   │   └── setting.py       # settings table
│   ├── schemas/             # Pydantic validation schemas
│   │   ├── common.py        # Response wrappers, pagination
│   │   ├── health.py        # Health check schema
│   │   ├── host.py          # Host CRUD schemas
│   │   └── scan.py          # Scan schemas
│   ├── services/            # Business logic
│   │   ├── assessment/      # Assessment Engine (Phase 4)
│   │   │   ├── manager.py   # Central orchestrator
│   │   │   ├── pipeline.py  # Stage definitions + DAG resolution
│   │   │   ├── runner.py    # Background task execution
│   │   │   ├── lifecycle.py # Status state machines
│   │   │   ├── progress_tracker.py # Weight-based progress
│   │   │   ├── stage_manager.py    # Pluggable handlers
│   │   │   └── exceptions.py       # Engine exceptions
│   ├── utils/               # Helpers
│   └── main.py              # FastAPI app with lifespan events
├── alembic/                 # Database migrations
│   ├── versions/            # Migration versions
│   │   └── 001_initial_schema.py  # Initial 12-table migration
│   └── env.py               # Async Alembic environment
├── tests/                   # Pytest test suite
│   ├── conftest.py          # Async fixtures
│   └── test_health.py       # Health endpoint tests (5 cases)
├── alembic.ini              # Alembic configuration
├── pyproject.toml           # Ruff, isort, black, pytest config
├── .pre-commit-config.yaml  # Pre-commit hooks
└── requirements.txt         # Python dependencies
```

## Frontend Architecture

```
frontend/
├── src/
│   ├── components/
│   │   ├── layout/            # App shell components
│   │   │   ├── Sidebar.tsx    # Collapsible navigation (9 routes)
│   │   │   ├── Header.tsx     # Theme toggle + user avatar
│   │   │   ├── Breadcrumbs.tsx# Auto-generated breadcrumb trail
│   │   │   └── DashboardLayout.tsx  # Main layout shell
│   │   └── ui/                # Reusable component library
│   │       ├── Button.tsx     # 4 variants + loading state
│   │       ├── Card.tsx       # Section container with header
│   │       ├── Badge.tsx      # Status/tag indicator
│   │       ├── Table.tsx      # Generic typed data table
│   │       ├── Modal.tsx      # Dialog with backdrop
│   │       ├── StatCard.tsx   # Dashboard metric card
│   │       ├── ProgressBar.tsx# Animated progress indicator
│   │       ├── LoadingSpinner.tsx # Loading state
│   │       └── EmptyState.tsx # Empty data placeholder
│   ├── context/               # React context providers
│   │   ├── ThemeContext.tsx    # Dark/light theme + persistence
│   │   └── ToastContext.tsx   # Toast notification system
│   ├── hooks/                 # Custom React hooks
│   │   ├── useTheme.ts
│   │   ├── useToast.ts
│   │   └── useApi.ts          # Generic async state manager
│   ├── pages/                 # Page components (10 pages)
│   │   ├── Dashboard.tsx      # Mock stats, chart, health status
│   │   ├── Workspace.tsx      # Assessment workflow UI
│   │   ├── Hosts.tsx          # Host table with discovery
│   │   ├── Scanning.tsx       # Port scanner UI
│   │   ├── Vulnerabilities.tsx# Vulnerability listing
│   │   ├── Exploitation.tsx   # Metasploit module UI
│   │   ├── Packets.tsx        # PCAP capture UI
│   │   ├── Reports.tsx        # Report generation UI
│   │   ├── Settings.tsx       # Configuration page
│   │   ├── Error404.tsx       # 404 page
│   │   └── Error500.tsx       # 500 page
│   ├── services/              # API client layer
│   │   ├── api.ts             # Axios instance + interceptors
│   │   └── healthService.ts   # Health check API
│   ├── types/                 # TypeScript definitions
│   │   ├── common.ts          # ApiResponse, pagination, nav
│   │   ├── health.ts, host.ts, scan.ts, dashboard.ts
│   ├── router/index.tsx       # Route definitions (10 routes)
│   ├── utils/                 # Helpers + constants
│   ├── App.tsx                # Root component
│   ├── main.tsx               # Entry point
│   └── index.css              # Tailwind + custom utilities
├── package.json
├── vite.config.ts             # Vite + proxy config
├── tailwind.config.js         # Custom theme (colors, fonts)
└── tsconfig.json              # Strict TypeScript config
```

### Key Frontend Features

| Feature | Implementation |
|---------|---------------|
| Build Tool | Vite 5 (fast HMR, native ESM) |
| Styling | Tailwind CSS 3 with dark mode via `class` strategy |
| Routing | React Router v6 with nested layouts |
| State Management | React Context + custom hooks (no Redux overhead) |
| HTTP Client | Axios with auth/error interceptors |
| Charts | Recharts (PieChart on Dashboard) |
| Theme | Dark/light toggle, `localStorage` persistence |
| Type Safety | Strict TypeScript across all 51 source files |
| API Integration | Vite dev proxy `/api` → backend `:8000` |

### Backend Features

| Feature | Implementation |
|---------|---------------|
| Async Database | SQLAlchemy 2.0 + asyncpg, `AsyncSession`, async lifespan |
| UUID PKs | All tables use UUID primary keys |
| JSONB Columns | Scan parameters, protocol stats, log details |
| Structured Logging | Loguru with JSON output + 10 MB file rotation |
| Exception Hierarchy | 5 custom exception types with structured error responses |
| Config Validation | Environment variables validated on startup |
| API Versioning | `/api/v1/` prefix with router aggregation |
| Dependency Injection | `get_db()` with automatic commit/rollback |
| Docker Support | Dockerfile + docker-compose (PostgreSQL + backend) |
| CI Ready | GitHub Actions workflow, pre-commit hooks configured |

---

## Virtual Lab Environment

### Network Topology

```
┌──────────────────────────────────────────────────────────────┐
│                    Host-Only Network                          │
│                    192.168.56.0/24                            │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │  Kali Linux  │    │Metasploitable│    │  Windows 7   │    │
│  │  192.168.56.10│   │  192.168.56.20│   │  192.168.56.30│   │
│  │  Attacker     │    │  Target 1     │    │  Target 2    │    │
│  └──────────────┘    └──────────────┘    └──────────────┘    │
│                              ┌──────────────┐                 │
│                              │Ubuntu Server │                 │
│                              │192.168.56.40 │ (Optional)      │
│                              └──────────────┘                 │
└──────────────────────────────────────────────────────────────┘
```

### IP Addressing Plan

| Machine | Role | IP Address | vCPU | RAM | Disk |
|---------|------|------------|------|-----|------|
| Host Machine | Management | 192.168.56.1 | — | — | — |
| Kali Linux | Attacker | 192.168.56.10 | 2 | 4 GB | 60 GB |
| Metasploitable2 | Target 1 | 192.168.56.20 | 1 | 512 MB | 8 GB |
| Windows 7 (Unpatched) | Target 2 | 192.168.56.30 | 2 | 2 GB | 40 GB |
| Ubuntu Server | Target 3 (Optional) | 192.168.56.40 | 1 | 1 GB | 20 GB |

---

## Features

- **Host Discovery** — Nmap ping sweep, ARP discovery, live host detection
- **Port Scanner** — TCP SYN, UDP, full port range, version detection, OS fingerprinting
- **Service Enumeration** — Banner grabbing, service identification, version detection
- **Vulnerability Assessment** — OpenVAS/Nessus integration, CVE identification, risk scoring
- **CVE Intelligence** — CVSS v3 scoring, CWE mapping, exploit availability correlation
- **Controlled Exploitation** — Metasploit RPC integration, session management, evidence capture
- **Privilege Escalation** — Local enumeration, kernel exploit matching
- **Lateral Movement** — Network pivoting, credential reuse, internal reconnaissance
- **Packet Analysis** — PCAP capture, protocol statistics, TCP stream reassembly
- **Report Generation** — Executive & technical reports in HTML, PDF, and Markdown

---

## Project Structure

```
├── backend/               # FastAPI Python application (Phase 2)
│   ├── app/
│   │   ├── api/           # REST API route handlers
│   │   ├── core/          # Config, database, logging, exceptions
│   │   ├── models/        # 12 SQLAlchemy ORM models
│   │   ├── schemas/       # Pydantic validation schemas
│   │   ├── services/      # Business logic (in progress)
│   │   └── main.py        # FastAPI app with lifespan
│   ├── alembic/           # DB migrations
│   └── tests/             # Pytest suite
├── frontend/              # React + TypeScript application (Phase 3)
│   ├── src/
│   │   ├── components/    # Layout + UI component library (9 components)
│   │   ├── context/       # Theme + Toast providers
│   │   ├── hooks/         # Custom React hooks
│   │   ├── pages/         # 10 page views (Dashboard to Settings)
│   │   ├── services/      # Axios API client
│   │   ├── types/         # TypeScript type definitions
│   │   ├── router/        # Route definitions
│   │   └── utils/         # Constants and helpers
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   └── tsconfig.json
├── database/              # Schema migrations and scripts
├── automation/            # Python automation scripts
├── docs/                  # Architecture and design documentation
├── reports/               # Generated report output files
├── screenshots/           # Phase screenshots
├── wireshark/             # PCAP capture files
├── docker/                # Docker configuration files
├── scripts/               # Utility shell scripts
└── .github/workflows/     # CI/CD pipeline configuration
```

---

## Documentation

All project documentation is in the `docs/` directory:

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | 6-layer system architecture with data flow |
| [Database Schema](docs/DATABASE_SCHEMA.md) | 12-table relational schema with SQL DDL |
| [API Plan](docs/API_PLAN.md) | 40+ REST endpoints across 12 resource groups |
| [Lab Setup Guide](docs/LAB_SETUP_GUIDE.md) | Complete virtual lab setup with topology |
| [Lab Credentials](docs/LAB_CREDENTIALS.md) | All VM credentials (isolated lab only) |
| [Validation Checklist](docs/VALIDATION_CHECKLIST.md) | Lab connectivity verification checklist |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |

---

## Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- VirtualBox 7+ or VMware Workstation
- 16 GB+ RAM on host machine
- Docker (optional, for containerized setup)

### Quick Start

```bash
# Clone and enter
git clone https://github.com/yourusername/network-vapt-lab.git
cd network-vapt-lab

# ── Backend ──────────────────────────────────
cd backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r requirements.txt

# Ensure PostgreSQL is running with database 'vapt_db'
# Copy and edit .env
cp ../.env.example .env

# Run migrations
alembic upgrade head

# Start backend (Terminal 1)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# ── Frontend ─────────────────────────────────
cd ../frontend

# Install dependencies
npm install

# Start frontend (Terminal 2)
npm run dev
```

### Docker Setup

```bash
docker-compose -f docker/docker-compose.yml up -d
# Backend:  http://localhost:8000
# Swagger:  http://localhost:8000/docs
# Health:   http://localhost:8000/api/v1/health
```

### Testing

```bash
# Backend tests
cd backend
pytest tests/ -v --asyncio-mode=auto

# Frontend build check
cd frontend
npm run build
```

### Access Points

| Service | URL |
|---------|-----|
| Frontend (dev) | `http://localhost:5173` |
| Backend API | `http://localhost:8000` |
| Swagger Docs | `http://localhost:8000/docs` |
| Health Check | `http://localhost:8000/api/v1/health` |

---

## API Documentation

Once the backend is running:
- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`
- **Health Check:** `GET http://localhost:8000/api/v1/health`

---

## Development Phases

| # | Phase | Description | Status |
|---|-------|-------------|--------|
| 0 | Project Planning | Architecture, DB schema, API plan | ✅ Complete |
| 1 | Virtual Lab Setup | Hypervisor, VMs, networking, validation | ✅ Complete |
| 2 | Backend Foundation | FastAPI, SQLAlchemy, Alembic, config, logging, tests | ✅ Complete |
| 3 | Frontend Foundation | React, TypeScript, Tailwind, routing, API client, 10 pages | ✅ Complete |
| 4 | Assessment Engine Foundation | State machine, pipeline, runner, progress tracker, CRUD APIs | ✅ Complete |
| 5 | Dashboard Development | Real API integration, live data, enhanced charts | ⏳ |
| 6 | Assessment Workspace | Assessment configuration UI | ⏳ |
| 7 | Host Discovery | Nmap integration, live host detection | ⏳ |
| 8 | Port Scanner | TCP/UDP scanning, version/OS detection | ⏳ |
| 9 | Service Enumeration | Banner grabbing, service identification | ⏳ |
| 10 | Vulnerability Assessment | OpenVAS/Nessus integration, CVE parsing | ⏳ |
| 11 | CVE Intelligence | CVSS, CWE, MITRE ATT&CK correlation | ⏳ |
| 12 | Exploit Verification | Metasploit RPC, controlled exploitation | ⏳ |
| 13 | Privilege Escalation | Local enumeration, exploit matching | ⏳ |
| 14 | Lateral Movement | Pivoting, credential harvesting | ⏳ |
| 15 | Packet Analysis | PCAP capture, protocol inspection | ⏳ |
| 16 | Report Generation | HTML, PDF, Markdown report export | ⏳ |
| 17 | Testing | Unit, integration, API, UI testing | ⏳ |
| 18 | Documentation | User guide, installation guide, final docs | ⏳ |
| 19 | GitHub Release | Version tag, release notes, final review | ⏳ |

---

## License

This project is licensed under the MIT License.

## Ethical Use

This platform is designed exclusively for **educational and authorized penetration testing** within isolated laboratory environments. Unauthorized use against systems without explicit permission is illegal.
