# API Plan

## Network VAPT Platform — REST API Endpoints

**Base URL:** `/api/v1`

---

## 1. Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard/summary` | Overall platform statistics |
| GET | `/dashboard/risk-distribution` | Vulnerability severity breakdown |
| GET | `/dashboard/recent-scans` | Last 5 scans with status |
| GET | `/dashboard/host-summary` | Live host count by OS |

---

## 2. Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scans` | Create and start a new scan |
| GET | `/scans` | List all scans (paginated) |
| GET | `/scans/{scan_id}` | Get scan details and status |
| DELETE | `/scans/{scan_id}` | Delete a scan record |
| POST | `/scans/{scan_id}/cancel` | Cancel a running scan |

---

## 3. Host Discovery

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/hosts/discover` | Run Nmap host discovery |
| GET | `/hosts` | List all discovered hosts (paginated) |
| GET | `/hosts/{host_id}` | Get host details |
| DELETE | `/hosts/{host_id}` | Remove a host record |
| GET | `/hosts/{host_id}/ports` | List ports for a specific host |

---

## 4. Port Scanning

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scans/{scan_id}/port-scan` | Run port scan on discovered hosts |
| GET | `/ports` | List all ports (filterable by state, protocol) |
| GET | `/ports/{port_id}` | Get port details |
| GET | `/ports/{port_id}/services` | Get services on a specific port |

---

## 5. Service Enumeration

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scans/{scan_id}/service-enum` | Run service version detection |
| GET | `/services` | List all enumerated services (paginated) |
| GET | `/services/{service_id}` | Get service details |

---

## 6. Vulnerability Assessment

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scans/{scan_id}/vuln-scan` | Start OpenVAS/Nessus vulnerability scan |
| GET | `/vulnerabilities` | List all vulnerabilities (filterable) |
| GET | `/vulnerabilities/{vuln_id}` | Get vulnerability details |
| GET | `/hosts/{host_id}/vulnerabilities` | Vulnerabilities for a host |

---

## 7. CVE Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/cves` | List all CVEs (paginated, filterable) |
| GET | `/cves/{cve_id}` | Get CVE details |
| GET | `/cves/{cve_id}/exploits` | Available exploits for a CVE |
| POST | `/cves/enrich` | Trigger CVE enrichment from NVD |

---

## 8. Exploitation

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/exploits` | List available Metasploit modules |
| GET | `/exploits/{exploit_id}` | Get exploit details |
| POST | `/exploits/run` | Execute a controlled exploit |
| GET | `/exploit-runs` | List exploit execution history |
| GET | `/exploit-runs/{run_id}` | Get exploit run details |

---

## 9. Packet Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/packets/capture` | Start a packet capture |
| POST | `/packets/stop` | Stop active capture |
| GET | `/packets/captures` | List packet captures |
| GET | `/packets/captures/{capture_id}` | Get capture details |
| GET | `/packets/captures/{capture_id}/stats` | Protocol statistics |
| GET | `/packets/analyze` | Analyze an uploaded PCAP file |

---

## 10. Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/reports/generate` | Generate a new report (HTML/PDF/MD) |
| GET | `/reports` | List generated reports |
| GET | `/reports/{report_id}` | Get report metadata |
| GET | `/reports/{report_id}/download` | Download report file |

---

## 11. Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/settings` | List all settings |
| PUT | `/settings/{key}` | Update a setting |
| GET | `/settings/network` | Network configuration (subnet, targets) |
| GET | `/settings/tools` | Tool paths and configurations |

---

## 12. Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/logs` | List logs (paginated, filterable) |
| GET | `/logs/{log_id}` | Get log details |
| DELETE | `/logs` | Clear log history |

---

## Response Format

### Success
```json
{
  "status": "success",
  "data": { ... },
  "message": "Operation completed",
  "timestamp": "2026-07-28T19:00:00Z"
}
```

### Paginated
```json
{
  "status": "success",
  "data": [ ... ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 150,
    "total_pages": 8
  },
  "timestamp": "2026-07-28T19:00:00Z"
}
```

### Error
```json
{
  "status": "error",
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "Scan with ID xyz not found"
  },
  "timestamp": "2026-07-28T19:00:00Z"
}
```
