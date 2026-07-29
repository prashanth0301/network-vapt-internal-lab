# API Specification

## Base URL

```
Development: http://localhost:8000/api/v1
Production:  https://vapt-platform.example.com/api/v1
```

## Authentication

All endpoints (when auth is enabled) require a Bearer token:

```
Authorization: Bearer <token>
```

## Common Response Format

```json
{
  "success": true,
  "data": {},
  "message": "Operation completed successfully",
  "errors": null
}
```

## Endpoint Groups

### 1. Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard/summary` | Overall statistics |
| GET | `/dashboard/hosts` | Host summary with counts |
| GET | `/dashboard/vulnerabilities` | Vulnerability distribution |
| GET | `/dashboard/risk-matrix` | Risk heatmap data |
| GET | `/dashboard/recent-scans` | Last 10 scan activities |

**GET /dashboard/summary Response:**
```json
{
  "total_hosts": 3,
  "total_ports": 47,
  "total_services": 23,
  "total_vulnerabilities": 38,
  "critical": 12,
  "high": 15,
  "medium": 8,
  "low": 3,
  "total_exploits": 6,
  "total_reports": 2
}
```

---

### 2. Hosts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/hosts` | List all discovered hosts |
| GET | `/hosts/{id}` | Host details with ports |
| POST | `/hosts/discover` | Run host discovery scan |
| DELETE | `/hosts/{id}` | Remove a host record |

**POST /hosts/discover**
```json
{
  "target": "192.168.56.0/24",
  "discovery_type": "ping_sweep"
}
```

**Response:**
```json
{
  "scan_id": "uuid",
  "hosts_found": 3,
  "hosts": [
    {
      "ip": "192.168.56.10",
      "mac": "00:0c:29:xx:xx:xx",
      "hostname": "kali",
      "status": "up",
      "os_hint": "Linux"
    }
  ],
  "duration_seconds": 12.5
}
```

---

### 3. Port Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan/start` | Start a new port scan |
| GET | `/scan/{scan_id}` | Get scan status/results |
| GET | `/scan/history` | List all previous scans |
| GET | `/ports` | Get all ports across hosts |
| GET | `/ports/{host_id}` | Get ports for a specific host |

**POST /scan/start**
```json
{
  "targets": ["192.168.56.20"],
  "scan_type": "tcp_syn",
  "ports": "1-10000",
  "service_detection": true,
  "os_detection": true
}
```

**Response:**
```json
{
  "scan_id": "uuid",
  "status": "running",
  "progress": 0
}
```

---

### 4. Services

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/services` | List all discovered services |
| GET | `/services/{host_id}` | Services for a host |
| POST | `/services/enumerate` | Run service enumeration |

---

### 5. Vulnerabilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vulnerabilities` | List all vulnerabilities |
| GET | `/vulnerabilities/{id}` | Vulnerability details with CVEs |
| GET | `/vulnerabilities/host/{host_id}` | Vulns for a specific host |
| POST | `/vulnerabilities/scan` | Start vulnerability scan |
| GET | `/vulnerabilities/scan/{scan_id}` | Vuln scan status |

---

### 6. CVE Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/cves` | List all mapped CVEs |
| GET | `/cves/{cve_id}` | CVE details (CVSS, CWE, exploits) |
| GET | `/cves/search?q={query}` | Search CVEs |
| POST | `/cves/enrich` | Enrich CVEs with exploit data |

---

### 7. Exploitation

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/exploit/modules` | List available Metasploit modules |
| GET | `/exploit/modules/search?q={query}` | Search modules |
| POST | `/exploit/run` | Execute an exploit |
| GET | `/exploit/sessions` | List active sessions |
| POST | `/exploit/sessions/{id}/interact` | Interact with session |
| DELETE | `/exploit/sessions/{id}` | Close session |

**POST /exploit/run**
```json
{
  "target": "192.168.56.20",
  "port": 445,
  "module": "exploit/multi/handler",
  "payload": "windows/meterpreter/reverse_tcp",
  "options": {
    "RHOSTS": "192.168.56.20",
    "RPORT": 445
  }
}
```

---

### 8. Packet Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/packets/capture` | Start a packet capture |
| GET | `/packets/captures` | List captures |
| GET | `/packets/captures/{id}` | Capture details |
| GET | `/packets/captures/{id}/stats` | Protocol statistics |
| GET | `/packets/captures/{id}/streams/{tcp_stream}` | TCP stream |
| DELETE | `/packets/captures/{id}` | Delete capture |

---

### 9. Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/reports/generate` | Generate a new report |
| GET | `/reports` | List all reports |
| GET | `/reports/{id}` | Report details |
| GET | `/reports/{id}/download/{format}` | Download (html/pdf/md) |
| DELETE | `/reports/{id}` | Delete a report |

**POST /reports/generate**
```json
{
  "scan_id": "uuid",
  "format": "pdf",
  "include_executive_summary": true,
  "include_technical_details": true,
  "include_recommendations": true
}
```

---

### 10. Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/settings` | Get application settings |
| PUT | `/settings` | Update settings |
| GET | `/settings/tools` | Security tools status |

---

### 11. Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/logs` | List logs (paginated) |
| GET | `/logs/export` | Export logs as file |

---

### 12. Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | API health check |

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "database": "connected",
  "uptime_seconds": 3600
}
```

---

## WebSocket Endpoints

```
ws://localhost:8000/ws/scan/{scan_id}    → Real-time scan progress
ws://localhost:8000/ws/exploit/{job_id}  → Real-time exploit output
ws://localhost:8000/ws/logs              → Real-time log stream
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request — Invalid parameters |
| 401 | Unauthorized — Authentication required |
| 403 | Forbidden — Insufficient permissions |
| 404 | Not Found — Resource not found |
| 409 | Conflict — Resource already exists |
| 422 | Unprocessable Entity — Validation error |
| 429 | Too Many Requests — Rate limit exceeded |
| 500 | Internal Server Error |
| 503 | Service Unavailable — Tool not found |

---

*End of API Specification*
