# Network VAPT Platform — System Design

**Version:** 1.0.0

---

## 1. System Architecture

The platform follows a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────┐
│                 Presentation Layer                   │
│            React + TypeScript + Tailwind             │
│         Dashboard │ Hosts │ Scans │ Reports          │
└──────────────────────┬──────────────────────────────┘
                       │ REST API (JSON)
┌──────────────────────▼──────────────────────────────┐
│                   API Layer                          │
│              FastAPI + Pydantic v2                   │
│         Validation │ Auth │ Rate Limiting            │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│               Business Logic Layer                   │
│     Services │ Orchestrators │ Workflow Managers     │
└──────┬───────────────────────────────────┬──────────┘
       │                                   │
┌──────▼──────────┐            ┌──────────▼──────────┐
│ Assessment Engine│           │   Report Generator   │
│ Tool Integration │           │ Jinja2 + WeasyPrint  │
└──────┬──────────┘            └─────────────────────┘
       │
┌──────▼──────────┐
│  Data Layer     │
│  SQLAlchemy ORM │
│  PostgreSQL DB  │
└─────────────────┘
```

---

## 2. Frontend Architecture

### Component Tree

```
App
├── Layout
│   ├── Sidebar (Navigation)
│   ├── Header (Status bar)
│   └── Main Content
├── Pages
│   ├── Dashboard
│   │   ├── StatCards (hosts, ports, vulns, exploits)
│   │   ├── RiskDistributionChart
│   │   ├── RecentScansTable
│   │   └── NetworkTopologyGraph
│   ├── Hosts
│   │   ├── HostList
│   │   └── HostDetail (ports, services, vulns)
│   ├── PortScanner
│   │   ├── ScanForm
│   │   ├── PortResultsTable
│   │   └── PortVisualisation
│   ├── Vulnerabilities
│   │   ├── VulnList
│   │   ├── VulnDetail (CVE, CVSS, CWE, exploit match)
│   │   └── RiskMatrix
│   ├── Exploitation
│   │   ├── ModuleBrowser
│   │   ├── SessionManager
│   │   └── EvidenceViewer
│   ├── PacketAnalysis
│   │   ├── CaptureList
│   │   ├── ProtocolBreakdown
│   │   └── PacketInspector
│   └── Reports
│       ├── ReportGenerator
│       ├── ReportPreview
│       └── ReportHistory
└── Shared Components
    ├── DataTable
    ├── StatusBadge
    ├── ProgressBar
    ├── Modal
    └── LoadingSpinner
```

### State Management
- React Context for global state (scan status, notifications)
- React Query (TanStack Query) for server state caching
- Local state via `useState` / `useReducer` per component

### Data Flow
```
User Action → Component → API Service (Axios) → FastAPI → Response → Component Re-render
```

---

## 3. Backend Architecture

### Application Structure

```
backend/
├── app/
│   ├── main.py                  # FastAPI app entry point
│   ├── api/
│   │   ├── __init__.py
│   │   ├── router.py            # Main router aggregation
│   │   ├── host_discovery.py    # Host discovery endpoints
│   │   ├── port_scanner.py      # Port scanning endpoints
│   │   ├── service_enum.py      # Service enumeration endpoints
│   │   ├── vulnerability.py     # Vulnerability assessment endpoints
│   │   ├── cve_intelligence.py  # CVE intelligence endpoints
│   │   ├── exploitation.py      # Exploitation endpoints
│   │   ├── privilege_esc.py     # Privilege escalation endpoints
│   │   ├── lateral_movement.py  # Lateral movement endpoints
│   │   ├── packet_analysis.py   # Packet analysis endpoints
│   │   ├── report.py            # Report generation endpoints
│   │   └── dashboard.py         # Dashboard statistics endpoints
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py            # Configuration (pydantic-settings)
│   │   ├── database.py          # Database engine + session
│   │   ├── logging.py           # Logging configuration
│   │   └── security.py          # Security utilities
│   ├── models/
│   │   ├── __init__.py
│   │   ├── host.py              # Host ORM model
│   │   ├── port.py              # Port ORM model
│   │   ├── service.py           # Service ORM model
│   │   ├── vulnerability.py     # Vulnerability ORM model
│   │   ├── cve.py               # CVE ORM model
│   │   ├── exploit.py           # Exploit ORM model
│   │   ├── scan.py              # Scan job ORM model
│   │   ├── report.py            # Report ORM model
│   │   ├── packet_capture.py    # Packet capture ORM model
│   │   └── setting.py           # Settings ORM model
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── host.py              # Pydantic schemas for hosts
│   │   ├── port.py              # Pydantic schemas for ports
│   │   ├── service.py           # Pydantic schemas for services
│   │   ├── vulnerability.py     # Pydantic schemas for vulns
│   │   ├── scan.py              # Pydantic schemas for scans
│   │   ├── report.py            # Pydantic schemas for reports
│   │   └── common.py            # Shared pagination, response schemas
│   ├── services/
│   │   ├── __init__.py
│   │   ├── nmap_service.py      # Nmap execution + parsing
│   │   ├── nessus_service.py    # Nessus API integration
│   │   ├── openvas_service.py   # OpenVAS API integration
│   │   ├── metasploit_service.py# Metasploit RPC integration
│   │   ├── wireshark_service.py # TShark/SSHARK execution + parsing
│   │   └── report_service.py    # Report generation logic
│   └── utils/
│       ├── __init__.py
│       ├── xml_parser.py        # Nmap XML output parser
│       ├── json_parser.py       # General JSON helpers
│       └── validators.py        # Input validation utilities
└── tests/
    ├── conftest.py
    ├── test_host_discovery.py
    ├── test_port_scanner.py
    ├── test_services.py
    └── test_reports.py
```

---

## 4. Database Design

### Entity-Relationship Model

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│   Hosts     │────>│    Ports     │────>│   Services    │
├─────────────┤     ├──────────────┤     ├───────────────┤
│ id (PK)     │     │ id (PK)      │     │ id (PK)       │
│ ip_address  │     │ host_id (FK) │     │ port_id (FK)  │
│ mac_address │     │ port_number  │     │ name          │
│ hostname    │     │ protocol     │     │ version       │
│ os_type     │     │ state        │     │ product       │
│ os_version  │     │ service_name │     │ extra_info    │
│ is_alive    │     │ created_at   │     │ created_at    │
│ discovered_at│    │              │     │               │
│ last_seen   │     │              │     │               │
└─────────────┘     └──────────────┘     └───────────────┘
       │                                           
       │       ┌──────────────────┐     ┌─────────────────┐
       └──────>│  Vulnerabilities │────>│      CVEs       │
               ├──────────────────┤     ├─────────────────┤
               │ id (PK)          │     │ id (PK)         │
               │ host_id (FK)     │     │ vuln_id (FK)    │
               │ port_id (FK)     │     │ cve_id          │
               │ nessus_plugin_id │     │ cvss_score      │
               │ openvas_oid      │     │ cvss_vector     │
               │ plugin_name      │     │ cwe_id          │
               │ severity         │     │ description     │
               │ description      │     │ published_date  │
               │ solution         │     │ exploit_available│
               │ risk_score       │     │ created_at      │
               │ created_at       │     └─────────────────┘
               └──────────────────┘              │
                                                  │
                         ┌────────────────┐       │
                         │   Exploits     │<──────┘
                         ├────────────────┤
                         │ id (PK)        │
                         │ cve_id (FK)    │
                         │ msf_module     │
                         │ module_type    │
                         │ target         │
                         │ description    │
                         │ rank           │
                         │ created_at     │
                         └────────────────┘

┌─────────────┐     ┌────────────────┐     ┌─────────────────┐
│  Scans      │     │ PacketCaptures │     │    Reports      │
├─────────────┤     ├────────────────┤     ├─────────────────┤
│ id (PK)     │     │ id (PK)        │     │ id (PK)         │
│ scan_type   │     │ file_name      │     │ title           │
│ target      │     │ file_path      │     │ report_type     │
│ status      │     │ file_size      │     │ format          │
│ started_at  │     │ protocol_count │     │ file_path       │
│ completed_at│     │ packet_count    │     │ generated_at    │
│ result_summary│   │ captured_at    │     │ created_at      │
│ created_at  │     │ created_at     │     └─────────────────┘
└─────────────┘     └────────────────┘

┌─────────────┐     ┌────────────────┐
│  Logs       │     │   Settings     │
├─────────────┤     ├────────────────┤
│ id (PK)     │     │ id (PK)        │
│ level       │     │ key            │
│ module      │     │ value          │
│ message     │     │ description    │
│ details     │     │ updated_at     │
│ timestamp   │     └────────────────┘
└─────────────┘
```

### SQLAlchemy Models Overview

- **Host** — `id`, `ip_address` (unique), `mac_address`, `hostname`, `os_type`, `os_version`, `is_alive`, `discovered_at`, `last_seen`
- **Port** — `id`, `host_id` (FK → hosts.id), `port_number`, `protocol` (tcp/udp), `state` (open/closed/filtered), `service_name`, `created_at`
- **Service** — `id`, `port_id` (FK → ports.id), `name`, `version`, `product`, `extra_info`, `created_at`
- **Vulnerability** — `id`, `host_id` (FK), `port_id` (FK), `nessus_plugin_id`, `openvas_oid`, `plugin_name`, `severity`, `description`, `solution`, `risk_score`, `created_at`
- **CVE** — `id`, `vuln_id` (FK), `cve_id` (e.g., CVE-2024-XXXX), `cvss_score`, `cvss_vector`, `cwe_id`, `description`, `published_date`, `exploit_available`, `created_at`
- **Exploit** — `id`, `cve_id` (FK), `msf_module` (full module path), `module_type` (exploit/auxiliary/post), `target`, `description`, `rank`, `created_at`
- **Scan** — `id`, `scan_type` (discovery/port/vuln/exploit), `target`, `status` (pending/running/completed/failed), `started_at`, `completed_at`, `result_summary`, `created_at`
- **PacketCapture** — `id`, `file_name`, `file_path`, `file_size`, `protocol_count`, `packet_count`, `captured_at`, `created_at`
- **Report** — `id`, `title`, `report_type` (executive/technical), `format` (html/pdf/md), `file_path`, `generated_at`, `created_at`
- **Log** — `id`, `level`, `module`, `message`, `details`, `timestamp`
- **Setting** — `id`, `key` (unique), `value`, `description`, `updated_at`

---

## 5. API Contract

### Dashboard
| Method | Endpoint            | Description                    |
|--------|---------------------|--------------------------------|
| GET    | `/api/v1/dashboard` | Aggregated dashboard stats     |
| GET    | `/api/v1/statistics`| Host/vuln/port/exploit counts  |

### Host Discovery
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/v1/hosts/discover`     | Start host discovery scan      |
| GET    | `/api/v1/hosts`              | List all discovered hosts      |
| GET    | `/api/v1/hosts/{id}`         | Get host detail                |
| DELETE | `/api/v1/hosts/{id}`         | Remove a host                  |

### Port Scanning
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/v1/ports/scan`         | Start port scan on target      |
| GET    | `/api/v1/ports`              | List all ports                 |
| GET    | `/api/v1/ports/{host_id}`    | Get ports for a host           |

### Service Enumeration
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/v1/services/enumerate` | Start service enumeration      |
| GET    | `/api/v1/services`           | List all services              |
| GET    | `/api/v1/services/{host_id}` | Get services for a host        |

### Vulnerability Assessment
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/v1/vulnerabilities/scan`| Start vulnerability scan       |
| GET    | `/api/v1/vulnerabilities`    | List all vulnerabilities       |
| GET    | `/api/v1/vulnerabilities/{host_id}`| Get vulns for a host     |

### CVE Intelligence
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| GET    | `/api/v1/cves`               | List all CVEs                  |
| GET    | `/api/v1/cves/{vuln_id}`     | Get CVEs for a vulnerability   |

### Exploitation
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| GET    | `/api/v1/exploits`           | List available exploits        |
| GET    | `/api/v1/exploits/{cve_id}`  | Get exploits for a CVE         |
| POST   | `/api/v1/exploits/run`       | Run an exploit module          |
| GET    | `/api/v1/exploits/sessions`  | List active sessions           |
| DELETE | `/api/v1/exploits/sessions/{id}`| Close a session             |

### Privilege Escalation
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/v1/privilege-escalation/check`| Check PE vectors on host|
| GET    | `/api/v1/privilege-escalation/results`| List PE results         |

### Lateral Movement
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/v1/lateral-movement/pivot`| Execute lateral movement    |
| GET    | `/api/v1/lateral-movement/paths`| List discovered attack paths|

### Packet Analysis
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/v1/packets/capture`    | Start packet capture           |
| POST   | `/api/v1/packets/upload`     | Upload PCAP file               |
| GET    | `/api/v1/packets/captures`   | List captures                  |
| GET    | `/api/v1/packets/{id}/stats` | Protocol statistics            |
| GET    | `/api/v1/packets/{id}/streams`| TCP stream data               |

### Reports
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| POST   | `/api/v1/reports/generate`   | Generate a report              |
| GET    | `/api/v1/reports`            | List all reports               |
| GET    | `/api/v1/reports/{id}`       | Download report file           |
| DELETE | `/api/v1/reports/{id}`       | Delete a report                |

### Scans
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| GET    | `/api/v1/scans`              | List all scan jobs             |
| GET    | `/api/v1/scans/{id}`         | Get scan status                |

### Settings
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| GET    | `/api/v1/settings`           | Get application settings       |
| PUT    | `/api/v1/settings`           | Update settings                |

### Health
| Method | Endpoint                     | Description                    |
|--------|------------------------------|--------------------------------|
| GET    | `/api/v1/health`             | Health check endpoint          |

---

## 6. Tool Integration Design

### Nmap Integration
- Execute via `subprocess` calling `nmap` with configurable flags
- Parse XML output (`-oX`) using `xml.etree.ElementTree`
- Support: ping sweep (`-sn`), TCP SYN (`-sS`), UDP (`-sU`), version detection (`-sV`), OS detection (`-O`), aggressive (`-A`)

### Nessus/OpenVAS Integration
- **Nessus:** REST API client using `requests` library (Nessus v10 API)
- **OpenVAS:** GMP (Greenbone Management Protocol) via `python-gvm`
- Both: Create scan config → launch scan → poll status → download results → parse into DB

### Metasploit Integration
- Use `msfrpc` library to communicate with Metasploit RPC daemon
- List modules → configure options → execute → collect evidence
- Manage sessions (list, interact, close)

### Wireshark Integration
- Execute `tshark` via subprocess for command-line packet analysis
- Parse output into structured protocol/packet data
- Support PCAP/PCAPNG file upload and analysis

---

## 7. Security Design

### Application Security
- Input validation via Pydantic schemas on all endpoints
- Structured exception handling with safe error messages
- CORS configuration for frontend origin only
- Rate limiting on scan initiation endpoints
- All tool output sanitised before storage
- No storage of credentials in plaintext

### Operational Security
- All scanning is restricted to target IP ranges (lab network)
- Scan targets are validated against allowed CIDR ranges
- Exploitation requires explicit user confirmation per module
- Session tokens are ephemeral and tied to lab context
- Logs capture all actions with timestamps for audit trail

---

## 8. Logging Strategy

| Level   | Use Case                              |
|---------|---------------------------------------|
| DEBUG   | Tool command output, raw parse results|
| INFO    | Scan start/complete, module execution |
| WARNING | Unusual service states, rate limits   |
| ERROR   | Tool failures, connection errors      |
| CRITICAL| Database failures, security violations|

Logs stored in `logs` table and optionally exported to rotating file handler.

---

## 9. Error Handling

All API endpoints follow a consistent error response schema:

```json
{
  "detail": {
    "code": "SCAN_FAILED",
    "message": "Port scan execution failed",
    "details": "Nmap returned exit code 1: Unable to open socket"
  }
}
```

HTTP status codes used:
- `200` — Success
- `201` — Created
- `400` — Bad Request (validation error)
- `404` — Resource not found
- `409` — Conflict (scan already running)
- `422` — Unprocessable Entity (Pydantic validation)
- `500` — Internal Server Error

---

## 10. Performance Considerations

- Scan operations run as background tasks (FastAPI `BackgroundTasks` or Celery)
- Database connection pooling via SQLAlchemy
- Pagination on all list endpoints (page, per_page)
- Frontend uses React Query for caching and deduplication
- Large file operations (PCAP) handled via streaming

---

## 11. Testing Strategy

| Type       | Tool           | Scope                              |
|------------|----------------|------------------------------------|
| Unit       | pytest         | Services, utilities, parsers       |
| API        | TestClient     | All REST endpoints                 |
| Integration| pytest + DB    | Database operations, tool calls    |
| Frontend   | Vitest         | Components, hooks, services        |

---

*End of System Design*
