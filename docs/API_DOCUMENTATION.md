# API Documentation

## Base URL

```
http://localhost:8000/api/v1
```

All endpoints are prefixed with `/api/v1`. The API is documented interactively at `http://localhost:8000/docs` (Swagger UI) and `http://localhost:8000/openapi.json` (OpenAPI spec).

---

## Authentication

### Login

```
POST /auth/login
```

**Request:**
```json
{
  "username": "admin",
  "password": "Admin@123",
  "remember_me": false
}
```

**Response (200):**
```json
{
  "status": "success",
  "data": {
    "access_token": "eyJhbGciOi...",
    "refresh_token": "eyJhbGciOi...",
    "token_type": "bearer"
  }
}
```

### Using Tokens

Include the access token in the `Authorization` header for all authenticated requests:

```
Authorization: Bearer <access_token>
```

### Token Refresh

```
POST /auth/refresh
Authorization: Bearer <refresh_token>
```

### Get Current User

```
GET /auth/me
```

### Logout

```
POST /auth/logout
```

---

## Common Response Formats

### Success (single resource)

```json
{
  "status": "success",
  "data": { ... },
  "message": "Resource retrieved",
  "timestamp": "2026-08-04T00:00:00Z"
}
```

### Success (paginated)

```json
{
  "status": "success",
  "data": [ ... ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 455,
    "total_pages": 23
  },
  "timestamp": "2026-08-04T00:00:00Z"
}
```

### Error

```json
{
  "status": "error",
  "error": {
    "error_code": "VALIDATION_ERROR",
    "message": "Invalid input",
    "details": { ... }
  },
  "timestamp": "2026-08-04T00:00:00Z"
}
```

---

## Endpoints Reference

### Health

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/health` | No | Database connectivity, uptime, version |

---

### Authentication & Users

| Method | Endpoint | Auth | Permissions | Description |
|--------|----------|------|-------------|-------------|
| `POST` | `/auth/login` | No | — | Authenticate and receive tokens |
| `POST` | `/auth/logout` | Yes | — | Invalidate current session |
| `POST` | `/auth/refresh` | Yes | — | Refresh access token |
| `GET` | `/auth/me` | Yes | — | Get current user profile |
| `GET` | `/roles` | Yes | `manage:users` | List all roles and permissions |
| `GET` | `/permissions` | Yes | — | Get current + all available permissions |
| `GET` | `/users` | Yes | `manage:users` | List/search users (paginated) |
| `GET` | `/users/{id}` | Yes | `manage:users` or own | Get user by ID |
| `POST` | `/users` | Yes | `manage:users` | Create a new user |
| `PUT` | `/users/{id}` | Yes | `manage:users` or own | Update user profile |
| `DELETE` | `/users/{id}` | Yes | `manage:users` | Delete a user |
| `PUT` | `/users/{id}/status` | Yes | `manage:users` | Activate/deactivate user |
| `PUT` | `/users/{id}/role` | Yes | `manage:users` | Change user role |
| `PUT` | `/users/{id}/password` | Yes | `manage:users` | Admin password reset |

---

### Dashboard

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/dashboard/summary` | Yes | Aggregated dashboard data |

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `assessment_id` | UUID | No | Filter all widgets by assessment |

**Response fields:** `severity_distribution`, `vulnerability_trend`, `top_open_ports`, `service_distribution`, `recent_assessments`, `recent_reports`, `top_vulnerable_hosts`, `risk_score`, `critical_count`, `exploit_available_count`, `scan_duration_stats`, `activity_timeline`, `totals`

---

### Assessments

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/assessments` | Yes | Create a new assessment |
| `GET` | `/assessments` | Yes | List assessments (paginated) |
| `GET` | `/assessments/statistics` | Yes | Assessment statistics |
| `GET` | `/assessments/{id}` | Yes | Get assessment details + progress |
| `GET` | `/assessments/{id}/summary` | Yes | Get assessment summary with findings |
| `POST` | `/assessments/{id}/start` | Yes | Start a pending assessment |
| `POST` | `/assessments/{id}/clone` | Yes | Clone an existing assessment |
| `POST` | `/assessments/{id}/cancel` | Yes | Cancel a running assessment |
| `DELETE` | `/assessments/{id}` | Yes | Delete assessment and all data |
| `GET` | `/assessments/pipelines/{scan_type}` | Yes | Get pipeline stage definitions |

**List Query Parameters:** `status`, `scan_type`, `search`, `target`, `date_from`, `date_to`, `page`, `per_page`

---

### Hosts

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/hosts` | Yes | List discovered hosts |
| `GET` | `/hosts/summary` | Yes | Host summary statistics |
| `GET` | `/hosts/{id}` | Yes | Get a single host |
| `GET` | `/hosts/{id}/details` | Yes | Full host details (ports, services, vulns, CVEs, exploits) |
| `DELETE` | `/hosts/{id}` | Yes | Delete a host record |
| `POST` | `/hosts/discover` | Yes | Trigger host discovery scan |

**List Query Parameters:** `status`, `alive_only`, `assessment_id`, `search`, `page`, `per_page`

---

### Ports

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/ports` | Yes | List all ports |
| `GET` | `/ports/{id}` | Yes | Get a single port |
| `GET` | `/ports/by-host/{host_id}` | Yes | Ports for a specific host |
| `GET` | `/ports/by-assessment/{assessment_id}` | Yes | Ports for a specific assessment |
| `POST` | `/ports/scan` | Yes | Initiate port scan |

**List Query Parameters:** `state`, `protocol`, `assessment_id`, `page`, `per_page`

---

### Services

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/services` | Yes | List enriched services |
| `GET` | `/services/categories` | Yes | List all service categories |
| `GET` | `/services/{id}` | Yes | Get a single service |
| `GET` | `/services/by-host/{host_id}` | Yes | Services for a specific host |
| `GET` | `/services/by-assessment/{assessment_id}` | Yes | Services for a specific assessment |
| `POST` | `/services/enrich` | Yes | Enrich services with intelligence |

**List Query Parameters:** `category`, `confidence_min`, `search`, `assessment_id`, `sort_by`, `sort_order`, `page`, `per_page`

---

### Vulnerabilities

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/vulnerabilities` | Yes | List vulnerabilities |
| `GET` | `/vulnerabilities/summary` | Yes | Severity counts summary |
| `GET` | `/vulnerabilities/scanners` | Yes | List scanner names |
| `GET` | `/vulnerabilities/{id}` | Yes | Get a single vulnerability |
| `GET` | `/vulnerabilities/by-host/{host_id}` | Yes | Vulns for a specific host |
| `GET` | `/vulnerabilities/by-service/{service_id}` | Yes | Vulns for a specific service |
| `GET` | `/vulnerabilities/by-assessment/{assessment_id}` | Yes | Vulns for a specific assessment |
| `POST` | `/vulnerabilities/scan` | Yes | Start vulnerability scan |

**List Query Parameters:** `severity`, `host_id`, `service_name`, `search`, `assessment_id`, `sort_by`, `sort_order`, `page`, `per_page`

---

### CVEs

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/cves` | Yes | List CVEs |
| `GET` | `/cves/search` | Yes | Search CVEs by query |
| `GET` | `/cves/high-risk` | Yes | List high-risk CVEs |
| `GET` | `/cves/statistics` | Yes | CVE statistics |
| `GET` | `/cves/{cve_id}` | Yes | Get a single CVE |
| `GET` | `/cves/by-vulnerability/{vuln_id}` | Yes | CVEs for a specific vulnerability |

**List Query Parameters:** `severity`, `vendor`, `product`, `year`, `search`, `kev_only`, `assessment_id`, `sort_by`, `sort_order`, `page`, `per_page`

---

### Exploits

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/exploits` | Yes | List exploits |
| `GET` | `/exploits/statistics` | Yes | Exploit statistics |
| `GET` | `/exploits/{id}` | Yes | Get a single exploit |
| `GET` | `/exploits/by-vulnerability/{vuln_id}` | Yes | Exploits for a vulnerability |
| `GET` | `/exploits/by-host/{host_id}` | Yes | Exploits for a host |
| `POST` | `/exploits/verify` | Yes | Execute exploit verification |
| `POST` | `/exploits/cancel` | Yes | Cancel a running exploit |

**List Query Parameters:** `status`, `provider`, `verified`, `execution_mode`, `search`, `assessment_id`, `sort_by`, `sort_order`, `page`, `per_page`

---

### Reports

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/reports` | Yes | List reports |
| `POST` | `/reports/generate` | Yes | Generate a new report |
| `GET` | `/reports/download/{id}` | Yes | Download report file |
| `PATCH` | `/reports/{id}` | Yes | Rename a report |
| `DELETE` | `/reports/{id}` | Yes | Delete a report |

**List Query Parameters:** `assessment_id`, `report_type`, `search`, `sort_by`, `sort_order`, `page`, `per_page`

**Generate Parameters:** `report_type` (executive/technical/compliance), `output_format` (json/html/pdf), `assessment_id`

---

### Packet Captures

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/captures` | Yes | List packet captures (`search` param: filter by filename, protocol, date) |
| `GET` | `/captures/protocols` | Yes | Protocol distribution stats |
| `GET` | `/captures/interfaces` | Yes | Available network interfaces |
| `GET` | `/captures/{id}` | Yes | Get capture details |
| `GET` | `/captures/{id}/packets` | Yes | List packets (paginated) |
| `GET` | `/captures/{id}/conversations` | Yes | List conversations |
| `GET` | `/captures/{id}/status` | Yes | Live capture status |
| `GET` | `/captures/{id}/download` | Yes | Download the stored PCAP file (`application/vnd.tcpdump.pcap`, `Content-Disposition: attachment`; 404 when the capture or its file is missing) |
| `DELETE` | `/captures/{id}` | Yes | Delete capture, packets, conversations, and PCAP file (admin only) |
| `POST` | `/captures/upload` | Yes | Upload PCAP file |
| `POST` | `/captures/start` | Yes | Start live capture |
| `POST` | `/captures/stop` | Yes | Stop running capture |

---

### Artifacts

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/artifacts` | Yes | List scan artifacts |
| `GET` | `/artifacts/{id}` | Yes | Get artifact details |
| `GET` | `/artifacts/{id}/files` | Yes | List files in artifact |
| `GET` | `/artifacts/{id}/download/{filename}` | Yes | Download/read artifact file |

---

### History

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `DELETE` | `/history/cleanup` | Yes | Delete history by time range or assessment |

---

### Settings

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/settings` | Yes | List settings |
| `PUT` | `/settings` | Yes (admin) | Update settings |
| `POST` | `/settings/reset` | Yes (admin) | Reset to defaults |
| `GET` | `/settings/system` | Yes | System information |
| `POST` | `/settings/logo` | Yes (admin) | Upload company logo |
| `GET` | `/settings/logo` | Yes | Get company logo |
| `DELETE` | `/settings/logo` | Yes (admin) | Remove company logo |

---

### Audit Logs

| Method | Endpoint | Auth | Permissions | Description |
|--------|----------|------|-------------|-------------|
| `GET` | `/audit-logs` | Yes | `view:audit` | Paginated audit log listing |
| `GET` | `/audit-logs/meta` | Yes | `view:audit` | Filter metadata (users, actions, statuses) |
| `GET` | `/audit-logs/export` | Yes | `view:audit` | Export as CSV or JSON |

**Query Parameters:** `user`, `action`, `status`, `date_from`, `date_to`, `search`, `sort_by`, `sort_order`, `page`, `per_page`

**Export Parameters:** `format` (csv/json)

---

## Permissions Matrix

| Permission | Admin | Analyst | Viewer |
|---|---|---|---|
| `create:assessment` | Yes | Yes | No |
| `delete:assessment` | Yes | No | No |
| `view:reports` | Yes | Yes | Yes |
| `manage:users` | Yes | No | No |
| `manage:settings` | Yes | No | No |
| `run:scans` | Yes | Yes | No |
| `export:reports` | Yes | Yes | No |
| `manage:integrations` | Yes | No | No |
| `view:audit` | Yes | Yes | No |

---

## Rate Limiting

The `/auth/login` endpoint is rate-limited to prevent brute-force attacks. Other endpoints do not have explicit rate limiting.

---

## Error Codes

| Status | Meaning |
|--------|---------|
| `200` | Success |
| `201` | Created |
| `400` | Bad request / validation error |
| `401` | Authentication required or invalid credentials |
| `403` | Insufficient permissions |
| `404` | Resource not found |
| `409` | Conflict (e.g., duplicate username) |
| `422` | Unprocessable entity |
| `500` | Internal server error |
