# Network VAPT Platform — Architecture

System architecture of the Internal Network Vulnerability Assessment & Penetration Testing Platform (v1.0).

---

## 1. System Flow

```mermaid
flowchart TD
    Browser[Browser] --> Frontend[React Frontend]
    Frontend --> API[FastAPI Backend]
    API --> Manager[Assessment Manager]
    Manager --> DB[(Database\nPostgreSQL 16)]
    DB --> Reports[Reports]
    Reports --> Capture[Packet Capture]
    Capture --> Audit[Audit Logs]
    Audit --> Docker[Docker]
```

---

## 2. Container Diagram

```mermaid
flowchart LR
    subgraph Docker["Docker Compose Environment"]
        DB[(vapt-db\nPostgreSQL 16\n:5432 internal)]
        BE[vapt-backend\nFastAPI + Uvicorn\n:8000]
        FE[vapt-frontend\nReact SPA (serve)\n:5173]
        LAB1[vapt-vulnapache\nVulnerable Apache target]
        LAB2[vapt-ftp\nFTP lab service]
    end

    User[User] -->|HTTP :5173| FE
    FE -->|HTTP /api/v1 :8000| BE
    BE -->|asyncpg :5432| DB
    BE -->|scan| LAB1
    BE -->|scan| LAB2
    BE -.->|reports/ screenshots/ wireshark/| DB
```

---

## 3. Component Diagram

```mermaid
flowchart TD
    subgraph Frontend["Frontend (React 18 + TypeScript)"]
        Pages[20 Pages] --> Services[18 API Services]
        Services --> Axios[Axios / JWT Interceptors]
    end

    subgraph Backend["Backend (FastAPI)"]
        Router[16 Routers / 94 Endpoints] --> Auth[Auth & RBAC]
        Router --> Engine[Assessment Engine]
        Engine --> Stages[6-Stage Pipeline]
        Stages --> Discovery[Host Discovery]
        Stages --> PortScan[Port Scan]
        Stages --> ServiceDet[Service Detection]
        Stages --> VulnScan[Vulnerability Scan]
        Stages --> Exploit[Exploit Verification]
        Router --> Reports[Report Service]
        Router --> Capture[Packet Capture Service]
        Router --> Audit[Audit Log Service]
    end

    subgraph External["External Integrations"]
        Nmap[Nmap]
        OpenVAS[OpenVAS]
        MSF[Metasploit RPC]
        NVD[NVD / EPSS / KEV]
        TShark[dumpcap / tshark]
    end

    Axios -->|REST JSON| Router
    Auth --> DB[(PostgreSQL 16\n17 tables)]
    Stages --> DB
    Reports --> DB
    Capture --> TShark
    VulnScan --> Nmap
    VulnScan --> OpenVAS
    Exploit --> MSF
    Exploit --> NVD
    Audit --> DB
```

---

## 4. Entity Relationship Diagram

```mermaid
erDiagram
    users ||--o{ audit_logs : "writes"
    assessments ||--o{ hosts : "discovers"
    assessments ||--o{ vulnerabilities : "finds"
    assessments ||--o{ reports : "generates"
    hosts ||--o{ ports : "exposes"
    hosts ||--o{ vulnerabilities : "affected by"
    hosts ||--o{ exploits : "targeted by"
    ports ||--o{ services : "runs"
    ports |o--o{ vulnerabilities : "on"
    services |o--o{ vulnerabilities : "in"
    services |o--o{ exploits : "on"
    vulnerabilities ||--o{ cves : "mapped to"
    vulnerabilities |o--o{ exploits : "exploited by"
```

---

## 5. Deployment Notes

- **Frontend:** served as a static production build on port 5173 (dev server proxies `/api` → `:8000`).
- **Backend:** FastAPI + Uvicorn on port 8000; auto-creates schema, seeds settings, and bootstraps the default administrator on first start.
- **Database:** PostgreSQL 16 with 17 tables, UUID primary keys, JSONB scan parameters.
- **Lab targets:** `vapt-vulnapache` and `vapt-ftp` containers simulate vulnerable services for authorized testing.
- **Volumes:** `reports/`, `screenshots/`, `wireshark/`, and backend logs are mounted into the backend container.
