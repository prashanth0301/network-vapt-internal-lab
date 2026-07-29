-- Network VAPT Lab - Database Schema
-- PostgreSQL 15+

-- Hosts table
CREATE TABLE hosts (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    mac_address VARCHAR(17),
    hostname VARCHAR(255),
    operating_system VARCHAR(255),
    os_cpe VARCHAR(255),
    device_type VARCHAR(100),
    status VARCHAR(20) DEFAULT 'unknown',  -- up, down, unknown
    first_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_target BOOLEAN DEFAULT FALSE
);

-- Ports table
CREATE TABLE ports (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL,  -- tcp, udp
    state VARCHAR(20) NOT NULL,     -- open, closed, filtered
    service_name VARCHAR(100),
    service_product VARCHAR(255),
    service_version VARCHAR(100),
    service_extra VARCHAR(255),
    is_udp BOOLEAN DEFAULT FALSE,
    last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host_id, port, protocol)
);

-- Services table (banner/version details)
CREATE TABLE services (
    id SERIAL PRIMARY KEY,
    port_id INTEGER REFERENCES ports(id) ON DELETE CASCADE,
    name VARCHAR(100),
    product VARCHAR(255),
    version VARCHAR(100),
    extra_info TEXT,
    protocol VARCHAR(50),
    banner TEXT,
    confidence INTEGER DEFAULT 0
);

-- Scans table (tracks assessment runs)
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    scan_type VARCHAR(50) NOT NULL,   -- discovery, port, service, vuln
    target VARCHAR(255),
    status VARCHAR(20) DEFAULT 'pending',  -- pending, running, completed, failed, cancelled
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INTEGER,
    parameters JSONB,
    result_summary JSONB,
    error_message TEXT
);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    port_id INTEGER REFERENCES ports(id) ON DELETE SET NULL,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    name VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20),           -- critical, high, medium, low, info
    cvss_score NUMERIC(3,1),
    cvss_vector VARCHAR(100),
    cve_ids TEXT[],                  -- Array of CVE IDs
    cwe_ids TEXT[],                  -- Array of CWE IDs
    solution TEXT,
    plugin_id VARCHAR(100),
    plugin_output TEXT,
    first_found TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_found TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- CVE Intelligence table
CREATE TABLE cve_intelligence (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20) UNIQUE NOT NULL,
    description TEXT,
    cvss_v3_score NUMERIC(3,1),
    cvss_v3_vector VARCHAR(100),
    cvss_v2_score NUMERIC(3,1),
    cwe_id VARCHAR(20),
    exploit_available BOOLEAN DEFAULT FALSE,
    has_metasploit_module BOOLEAN DEFAULT FALSE,
    metasploit_modules TEXT[],        -- Array of module paths
    attack_vector VARCHAR(50),
    attack_complexity VARCHAR(50),
    privileges_required VARCHAR(50),
    user_interaction VARCHAR(50),
    scope VARCHAR(50),
    published_date DATE,
    last_modified_date DATE,
    source_url TEXT
);

-- Exploits table
CREATE TABLE exploits (
    id SERIAL PRIMARY KEY,
    cve_id INTEGER REFERENCES cve_intelligence(id) ON DELETE CASCADE,
    module_name VARCHAR(500) NOT NULL,
    module_type VARCHAR(50),          -- exploit, auxiliary, post
    target_platform VARCHAR(100),
    target_port INTEGER,
    rank VARCHAR(50),                 -- excellent, great, good, normal, average, low, manual
    description TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP
);

-- Sessions table (Metasploit sessions)
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    session_type VARCHAR(50),         -- meterpreter, shell
    target_host VARCHAR(45),
    target_port INTEGER,
    exploit_module VARCHAR(500),
    payload VARCHAR(500),
    local_port INTEGER,
    platform VARCHAR(100),
    username VARCHAR(255),
    privileges VARCHAR(50),           -- user, admin, system
    session_opened TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    session_closed TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    notes TEXT
);

-- Packet Captures table
CREATE TABLE packet_captures (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255),
    file_path TEXT,
    file_size_bytes BIGINT,
    capture_filter VARCHAR(255),
    duration_seconds INTEGER,
    packet_count INTEGER,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    protocol_stats JSONB,
    top_talkers JSONB,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL
);

-- Reports table
CREATE TABLE reports (
    id SERIAL PRIMARY KEY,
    title VARCHAR(500) NOT NULL,
    report_type VARCHAR(20),          -- executive, technical, full
    format VARCHAR(10),               -- html, pdf, md
    file_path TEXT,
    file_size_bytes BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    generated_by VARCHAR(100),
    parameters JSONB,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL
);

-- Logs table
CREATE TABLE logs (
    id SERIAL PRIMARY KEY,
    level VARCHAR(10) NOT NULL,       -- DEBUG, INFO, WARNING, ERROR, CRITICAL
    module VARCHAR(100),
    message TEXT NOT NULL,
    details JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Settings table
CREATE TABLE settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT,
    category VARCHAR(100),
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX idx_hosts_status ON hosts(status);
CREATE INDEX idx_ports_host ON ports(host_id);
CREATE INDEX idx_ports_state ON ports(state);
CREATE INDEX idx_vulnerabilities_host ON vulnerabilities(host_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_cve_intelligence_id ON cve_intelligence(cve_id);
CREATE INDEX idx_logs_level ON logs(level);
CREATE INDEX idx_logs_timestamp ON logs(timestamp);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_type ON scans(scan_type);

-- Default settings
INSERT INTO settings (key, value, category, description) VALUES
('nmap_binary', 'nmap', 'tools', 'Path to Nmap binary'),
('metasploit_rpc_host', '127.0.0.1', 'tools', 'Metasploit RPC host'),
('metasploit_rpc_port', '55553', 'tools', 'Metasploit RPC port'),
('nessus_url', 'https://127.0.0.1:8834', 'tools', 'Nessus API URL'),
('lab_network', '192.168.56.0/24', 'lab', 'Target lab network CIDR'),
('report_output_dir', 'reports', 'reports', 'Report output directory');
