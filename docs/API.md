# API Reference

Base URL: `http://localhost:8000/api/v1`

## Hosts

| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| GET    | `/hosts`              | List all discovered hosts|
| GET    | `/hosts/{id}`         | Get host details         |
| POST   | `/hosts/discover`     | Run host discovery       |
| DELETE | `/hosts/{id}`         | Remove a host            |

## Scanning

| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| POST   | `/scan/start`         | Start a new port scan    |
| GET    | `/scan/status/{id}`   | Get scan status          |
| GET    | `/scan/history`       | List past scans          |
| GET    | `/scan/results/{id}`  | Get detailed scan results|

## Services

| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| GET    | `/services`           | List all detected services|
| GET    | `/services/{host}`    | Get services for a host  |

## Vulnerabilities

| Method | Endpoint                    | Description                     |
|--------|-----------------------------|---------------------------------|
| GET    | `/vulnerabilities`          | List all vulnerabilities        |
| GET    | `/vulnerabilities/{host}`   | Get vulnerabilities for a host  |
| POST   | `/vulnerabilities/scan`     | Run vulnerability assessment    |

## CVE Intelligence

| Method | Endpoint                   | Description                        |
|--------|----------------------------|------------------------------------|
| GET    | `/cve`                     | List all CVEs                      |
| GET    | `/cve/{id}`                | Get CVE details + exploit mapping  |
| GET    | `/cve/exploit-map`         | Get CVE-to-Metasploit mapping       |

## Exploitation

| Method | Endpoint              | Description                  |
|--------|-----------------------|------------------------------|
| POST   | `/exploit/verify`     | Verify an exploit            |
| GET    | `/exploit/sessions`   | List active sessions         |
| POST   | `/exploit/cleanup`    | Clean up sessions            |

## Privilege Escalation

| Method | Endpoint                       | Description                       |
|--------|--------------------------------|-----------------------------------|
| POST   | `/privesc/enumerate`           | Run local enumeration             |
| POST   | `/privesc/execute`             | Attempt privilege escalation      |

## Lateral Movement

| Method | Endpoint                       | Description                       |
|--------|--------------------------------|-----------------------------------|
| POST   | `/lateral/enumerate`           | Enumerate network targets         |
| POST   | `/lateral/execute`             | Execute lateral movement          |

## Packet Analysis

| Method | Endpoint              | Description                  |
|--------|-----------------------|------------------------------|
| POST   | `/packets/capture`    | Start a packet capture       |
| GET    | `/packets/captures`   | List captures                |
| GET    | `/packets/analyse/{id}` | Analyse a capture          |
| GET    | `/packets/protocols`  | Get protocol statistics      |
| GET    | `/packets/streams/{id}` | Get TCP streams            |

## Reports

| Method | Endpoint                  | Description                  |
|--------|---------------------------|------------------------------|
| POST   | `/reports/generate`       | Generate a report            |
| GET    | `/reports`                | List all reports             |
| GET    | `/reports/{id}`           | Get report details           |
| GET    | `/reports/{id}/download`  | Download report file         |

## Dashboard

| Method | Endpoint              | Description                  |
|--------|-----------------------|------------------------------|
| GET    | `/dashboard/stats`    | Get dashboard statistics     |
| GET    | `/dashboard/recent`   | Get recent activity          |
| GET    | `/dashboard/risk-summary` | Get risk distribution    |

---

## Response Format

All responses follow a consistent envelope:

```json
{
  "status": "success",
  "data": { ... },
  "message": "Operation completed",
  "timestamp": "2026-07-28T19:00:00Z"
}
```

Error responses:

```json
{
  "status": "error",
  "detail": "Description of the error",
  "code": "ERROR_CODE"
}
```
