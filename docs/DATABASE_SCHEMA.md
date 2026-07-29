# Database Schema

## Entity Relationship Diagram (Text)

```
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│      hosts       │───────│      ports       │───────│    services      │
│──────────────────│       │──────────────────│       │──────────────────│
│ id (PK)          │       │ id (PK)          │       │ id (PK)          │
│ ip               │       │ host_id (FK)     │       │ port_id (FK)     │
│ mac              │       │ port             │       │ name             │
│ hostname         │       │ protocol         │       │ version          │
│ os               │       │ state            │       │ product          │
│ os_accuracy      │       │ service_name     │       │ extra_info       │
│ status           │       │ service_version  │       │ ──────────       │
│ first_seen       │       │ reason           │       │ created_at       │
│ last_seen        │       │ ──────────       │       └──────────────────┘
│ ──────────       │       │ created_at       │
│ created_at       │       └──────────────────┘
│ updated_at       │
└──────────────────┘
        │
        │
        ▼
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│     scans        │       │ vulnerabilities  │      │ CVE              │
│──────────────────│       │──────────────────│       │──────────────────│
│ id (PK)          │       │ id (PK)          │       │ id (PK)          │
│ scan_type        │───────│ host_id (FK)     │───────│ vuln_id (FK)     │
│ target           │       │ scan_id (FK)     │       │ cve_id           │
│ status           │       │ port_id (FK)     │       │ cvss_score       │
│ started_at       │       │ plugin_id        │       │ cvss_vector      │
│ completed_at     │       │ plugin_name      │       │ cwe_id           │
│ duration_seconds │       │ severity         │       │ exploitability   │
│ parameters       │       │ cvss_score       │       │ metasploit_module│
│ error_message    │       │ description      │       │ attack_vector    │
│ result_summary   │       │ solution         │       │ ──────────       │
│ ──────────       │       │ references       │       │ created_at       │
│ created_at       │       │ ──────────       │       └──────────────────┘
└──────────────────┘       │ created_at       │
                           │ updated_at       │
                           └──────────────────┘
                                   │
                                   │
                                   ▼
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│    exploits      │       │    reports       │       │ activity_logs    │
│──────────────────│       │──────────────────│       │──────────────────│
│ id (PK)          │       │ id (PK)          │       │ id (PK)          │
│ vuln_id (FK)     │       │ title            │       │ action           │
│ host_id (FK)     │       │ scan_id (FK)     │       │ entity_type      │
│ module           │       │ format           │       │ entity_id        │
│ payload          │       │ file_path        │       │ details          │
│ options (JSON)   │       │ file_size_bytes  │       │ ip_address       │
│ status           │       │ include_exec_sum │       │ user_agent       │
│ session_id       │       │ include_tech     │       │ ──────────       │
│ output           │       │ include_recs     │       │ created_at       │
│ ──────────       │       │ generated_by     │       └──────────────────┘
│ executed_at      │       │ ──────────       │
│ created_at       │       │ created_at       │
└──────────────────┘       └──────────────────┘

┌──────────────────┐       ┌──────────────────┐
│  packet_captures │       │    settings      │
│──────────────────│       │──────────────────│
│ id (PK)          │       │ id (PK)          │
│ filename         │       │ key              │
│ file_path        │       │ value            │
│ file_size_bytes  │       │ category         │
│ duration_seconds │       │ description      │
│ protocol_count   │       │ ──────────       │
│ packet_count     │       │ created_at       │
│ filter           │       │ updated_at       │
── ──────────      │       └──────────────────┘
│ created_at       │
└──────────────────┘
```

---

## Table Definitions

### hosts

```sql
CREATE TABLE hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip              INET NOT NULL,
    mac             MACADDR,
    hostname        VARCHAR(255),
    os              VARCHAR(255),
    os_accuracy     INTEGER CHECK (os_accuracy BETWEEN 0 AND 100),
    status          VARCHAR(20) DEFAULT 'unknown',
    first_seen      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(ip)
);
CREATE INDEX idx_hosts_ip ON hosts(ip);
CREATE INDEX idx_hosts_status ON hosts(status);
```

### ports

```sql
CREATE TABLE ports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol        VARCHAR(10) DEFAULT 'tcp',
    state           VARCHAR(20) DEFAULT 'unknown',
    service_name    VARCHAR(255),
    service_version VARCHAR(255),
    reason          VARCHAR(100),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(host_id, port, protocol)
);
CREATE INDEX idx_ports_host ON ports(host_id);
CREATE INDEX idx_ports_state ON ports(state);
```

### services

```sql
CREATE TABLE services (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    port_id         UUID NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(255),
    product         VARCHAR(255),
    extra_info      TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_services_port ON services(port_id);
CREATE INDEX idx_services_name ON services(name);
```

### scans

```sql
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type       VARCHAR(50) NOT NULL,
    target          VARCHAR(255) NOT NULL,
    status          VARCHAR(20) DEFAULT 'pending',
    started_at      TIMESTAMP WITH TIME ZONE,
    completed_at    TIMESTAMP WITH TIME ZONE,
    duration_seconds NUMERIC(10,2),
    parameters      JSONB,
    error_message   TEXT,
    result_summary  JSONB,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_scans_type ON scans(scan_type);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
```

### vulnerabilities

```sql
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_id         UUID REFERENCES scans(id) ON DELETE SET NULL,
    port_id         UUID REFERENCES ports(id) ON DELETE SET NULL,
    plugin_id       VARCHAR(100),
    plugin_name     VARCHAR(500),
    severity        VARCHAR(20) CHECK (severity IN ('critical','high','medium','low','info')),
    cvss_score      NUMERIC(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    description     TEXT,
    solution        TEXT,
    references      JSONB,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_vulns_host ON vulnerabilities(host_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_cvss ON vulnerabilities(cvss_score DESC);
```

### cves

```sql
CREATE TABLE cves (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id           UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cve_id            VARCHAR(20) NOT NULL,
    cvss_score        NUMERIC(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_vector       VARCHAR(100),
    cwe_id            VARCHAR(20),
    exploitability    NUMERIC(3,1),
    metasploit_module VARCHAR(500),
    attack_vector     VARCHAR(50),
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(vuln_id, cve_id)
);
CREATE INDEX idx_cves_cve_id ON cves(cve_id);
CREATE INDEX idx_cves_msf_module ON cves(metasploit_module);
```

### exploits

```sql
CREATE TABLE exploits (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id         UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    module          VARCHAR(500) NOT NULL,
    payload         VARCHAR(500),
    options         JSONB,
    status          VARCHAR(20) DEFAULT 'pending',
    session_id      VARCHAR(100),
    output          TEXT,
    executed_at     TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_exploits_host ON exploits(host_id);
CREATE INDEX idx_exploits_status ON exploits(status);
```

### reports

```sql
CREATE TABLE reports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title             VARCHAR(500) NOT NULL,
    scan_id           UUID REFERENCES scans(id) ON DELETE SET NULL,
    format            VARCHAR(10) CHECK (format IN ('html','pdf','md')),
    file_path         VARCHAR(1000),
    file_size_bytes   BIGINT,
    include_exec_sum  BOOLEAN DEFAULT TRUE,
    include_tech      BOOLEAN DEFAULT TRUE,
    include_recs      BOOLEAN DEFAULT TRUE,
    generated_by      VARCHAR(255) DEFAULT 'system',
    created_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_reports_scan ON reports(scan_id);
CREATE INDEX idx_reports_format ON reports(format);
```

### packet_captures

```sql
CREATE TABLE packet_captures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename        VARCHAR(500) NOT NULL,
    file_path       VARCHAR(1000) NOT NULL,
    file_size_bytes BIGINT,
    duration_seconds NUMERIC(10,2),
    protocol_count  JSONB,
    packet_count    INTEGER,
    filter          VARCHAR(500),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### activity_logs

```sql
CREATE TABLE activity_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action          VARCHAR(100) NOT NULL,
    entity_type     VARCHAR(50),
    entity_id       VARCHAR(100),
    details         JSONB,
    ip_address      INET,
    user_agent      VARCHAR(500),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX idx_logs_action ON activity_logs(action);
CREATE INDEX idx_logs_created ON activity_logs(created_at DESC);
```

### settings

```sql
CREATE TABLE settings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key             VARCHAR(255) NOT NULL UNIQUE,
    value           TEXT NOT NULL,
    category        VARCHAR(100),
    description     TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

---

## Relationships Summary

| Parent | Child | Type |
|--------|-------|------|
| hosts | ports | One-to-Many |
| hosts | vulnerabilities | One-to-Many |
| hosts | exploits | One-to-Many |
| ports | services | One-to-Many |
| scans | vulnerabilities | One-to-Many |
| vulnerabilities | cves | One-to-Many |
| vulnerabilities | exploits | One-to-Many |

---

## SQLAlchemy Model Naming Convention

```
Model:      Host, Port, Service, Scan, Vulnerability, CVE, Exploit, Report, PacketCapture, ActivityLog, Setting
Table:      hosts, ports, services, scans, vulnerabilities, cves, exploits, reports, packet_captures, activity_logs, settings
```

---

*End of Database Schema*
