# System Architecture

## Overview

The Network VAPT Platform follows a **layered architecture** with six distinct layers communicating via REST APIs and a shared PostgreSQL database.

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                           │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ Dashboard│  │   Hosts  │  │  Vulns   │  │  Reports │  Pages │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Topology│  │Exploits  │  │ Packets  │  │ Settings │  Pages │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│                                                                  │
│  React + TypeScript + Tailwind CSS + Recharts                   │
└──────────────────────────┬───────────────────────────────────────┘
                           │ HTTP / REST
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                      API LAYER (FastAPI)                         │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ /hosts   │  │ /scan    │  │ /vulns   │  │ /exploit │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │ /packets │  │ /report  │  │/dashboard│  │ /settings│        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│                                                                  │
│  Pydantic Validation → Rate Limiting → Logging Middleware       │
└──────────────────────────┬───────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   BUSINESS LOGIC LAYER                           │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                 Orchestration Engine                      │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │    │
│  │  │ Discovery│  │  Scanner │  │  Enum    │  │  Vuln   │ │    │
│  │  │ Manager  │  │  Manager │  │  Manager │  │  Manager│ │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │    │
│  │  │  CVE     │  │ Exploit  │  │ Packet   │  │ Report  │ │    │
│  │  │ Manager  │  │ Manager  │  │ Manager  │  │ Manager │ │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │    │
│  └──────────────────────────────────────────────────────────┘    │
└──────────────────────────┬───────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                   ASSESSMENT ENGINE LAYER                        │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │  Nmap    │  │Nessus/   │  │Metasploit│  │Wireshark │        │
│  │ Wrapper  │  │OpenVAS   │  │   RPC    │  │ tshark   │        │
│  │          │  │Wrapper   │  │ Client   │  │Wrapper   │        │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘        │
│                                                                  │
│  Subprocess → XML/JSON Parse → Structured Data                  │
└──────────────────────────┬───────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                     DATABASE LAYER (PostgreSQL)                  │
│                                                                  │
│  hosts ── ports ── services ── vulns ── cves ── exploits        │
│       └── scans ── reports ── logs ── settings                  │
│                                                                  │
│  SQLAlchemy ORM → Alembic Migrations → Connection Pooling       │
└──────────────────────────┬───────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│                 VIRTUAL NETWORK LABORATORY                       │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │  Kali Linux   │  │Metasploitable│  │  Windows 7    │          │
│  │  192.168.56.10│  │192.168.56.20 │  │192.168.56.30  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
│                                                                  │
│  Host-Only Network — 192.168.56.0/24                             │
└──────────────────────────────────────────────────────────────────┘
```

---

## Layer Descriptions

### 1. Presentation Layer (Frontend)
- Single Page Application built with React + TypeScript
- Tailwind CSS for responsive, dark-themed UI
- Recharts for interactive vulnerability charts
- Axios for REST API communication with the backend
- React Router for client-side navigation (10+ pages)

### 2. API Layer (FastAPI)
- RESTful API with automatic OpenAPI/Swagger documentation
- Pydantic models for request/response validation
- Middleware for logging, CORS, error handling
- Async endpoints for long-running scan operations
- WebSocket support for real-time scan progress

### 3. Business Logic Layer
- **Orchestration Engine**: Coordinates multi-step assessment workflows
- **Discovery Manager**: Nmap ping sweep, ARP discovery
- **Scanner Manager**: TCP/UDP port scanning, OS detection
- **Enum Manager**: Service version detection, banner grabbing
- **Vuln Manager**: Vulnerability scan orchestration and parsing
- **CVE Manager**: CVE correlation, CVSS scoring, exploit mapping
- **Exploit Manager**: Metasploit RPC communication, session handling
- **Packet Manager**: PCAP parsing, protocol analysis, stream reassembly
- **Report Manager**: Jinja2 templating, PDF generation, Markdown export

### 4. Assessment Engine Layer
- Thin wrappers around CLI security tools
- Subprocess execution with timeout and error handling
- XML/JSON output parsing into structured Python objects
- Safe parameter construction to prevent injection

### 5. Database Layer
- PostgreSQL with SQLAlchemy ORM
- Alembic for schema migrations
- Connection pooling for performance
- Indexed columns for fast queries on large scan results

### 6. Virtual Network Laboratory
- VirtualBox Host-Only Ethernet Adapter
- Static IP assignments for predictable addressing
- Isolated from host and external networks

---

## Data Flow — Full Assessment

```
User clicks "Start Assessment"
        │
        ▼
Frontend POST /assessment/start
        │
        ▼
Backend creates Scan record (status: running)
        │
        ▼
┌───────────────────────────────────────────┐
│ 1. Host Discovery                          │
│    → Nmap ping sweep (192.168.56.0/24)    │
│    → Store live hosts in DB               │
│    → Emit WebSocket progress event        │
└───────────────────┬───────────────────────┘
                    ▼
┌───────────────────────────────────────────┐
│ 2. Port Scan (for each host)              │
│    → Nmap -sS -sU -sV -O                 │
│    → Store ports, services, OS in DB      │
│    → Emit WebSocket progress event        │
└───────────────────┬───────────────────────┘
                    ▼
┌───────────────────────────────────────────┐
│ 3. Service Enumeration                    │
│    → Nmap -sV --version-intensity 9       │
│    → Store service details in DB          │
│    → Emit WebSocket progress event        │
└───────────────────┬───────────────────────┘
                    ▼
┌───────────────────────────────────────────┐
│ 4. Vulnerability Assessment               │
│    → OpenVAS/Nessus scan targets          │
│    → Parse results → Store vulns + CVEs   │
│    → Emit WebSocket progress event        │
└───────────────────┬───────────────────────┘
                    ▼
┌───────────────────────────────────────────┐
│ 5. CVE Correlation                        │
│    → Query CVE database                   │
│    → Map CVSS, CWE, EPSS scores           │
│    → Match with Metasploit modules        │
│    → Store enriched vulnerability data    │
│    → Emit WebSocket progress event        │
└───────────────────┬───────────────────────┘
                    ▼
┌───────────────────────────────────────────┐
│ 6. Exploit Verification (user-initiated)  │
│    → User selects target + exploit        │
│    → Backend invokes Metasploit via RPC   │
│    → Session created → Evidence captured  │
│    → Store result in DB                   │
└───────────────────┬───────────────────────┘
                    ▼
┌───────────────────────────────────────────┐
│ 7. Report Generation (user-initiated)     │
│    → Aggregate all findings from DB       │
│    → Render Jinja2 HTML template          │
│    → Convert to PDF via WeasyPrint        │
│    → Export Markdown version              │
│    → Store report record in DB            │
└───────────────────────────────────────────┘
```

---

## Security Architecture

- **Input Validation**: All API parameters validated via Pydantic
- **Command Injection Prevention**: Tool arguments built with parameterized lists, not string concatenation
- **Isolated Execution**: All security tools run within the lab network only
- **Safe Defaults**: Scan targets restricted to RFC 1918 private ranges by default
- **Audit Logging**: Every action logged with timestamp, user, and parameters
- **Error Handling**: Structured exception handling across all layers

---

## Technology Decisions

| Decision | Rationale |
|----------|-----------|
| FastAPI over Flask | Async support, auto Swagger, Pydantic integration |
| SQLAlchemy over raw SQL | ORM portability, migration support, relationship management |
| React over Vue/Angular | Largest ecosystem, TypeScript maturity, corporate adoption |
| Tailwind over Bootstrap | Utility-first, smaller bundles, easier customization |
| PostgreSQL over MySQL | Advanced JSON support, better indexing, CTEs |
| Jinja2 over PDF libs | Template reuse, HTML-to-PDF via WeasyPrint |
| WebSocket over polling | Real-time scan progress without HTTP overhead |

---

*End of Architecture Document*
