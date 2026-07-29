# System Design

## Project Title

**Network Vulnerability Assessment and Penetration Testing (Internal Network Lab)**

---

# Version

Version: 1.0

---

# 1. Introduction

The Network Vulnerability Assessment and Penetration Testing (Internal Network Lab) is designed as a modular, full-stack cybersecurity platform that automates the complete internal network assessment lifecycle.

The application integrates industry-standard security tools such as Nmap, Nessus/OpenVAS, Metasploit Framework, and Wireshark into a centralized web platform, allowing users to perform network discovery, vulnerability assessment, controlled penetration testing, packet analysis, and professional report generation from a single dashboard.

The platform follows a layered architecture to ensure scalability, maintainability, and modular development.

---

# 2. System Architecture

The application consists of six major layers:

1. Presentation Layer (Frontend)
2. API Layer (FastAPI)
3. Business Logic Layer
4. Assessment Engine
5. Database Layer
6. Virtual Network Laboratory

Overall Data Flow

User

↓

React Frontend

↓

REST API

↓

FastAPI Backend

↓

Assessment Engine

↓

Database

↓

Virtual Network Lab

---

# 3. Frontend Design

The frontend provides an interactive dashboard for monitoring assessments and managing scans.

Technology Stack

- React
- TypeScript
- Tailwind CSS
- Axios
- React Router
- Recharts

Frontend Pages

- Dashboard
- Hosts
- Network Topology
- Port Scan Results
- Service Enumeration
- Vulnerability Assessment
- Exploitation
- Packet Analysis
- Reports
- Settings
- About

---

# 4. Backend Design

The backend acts as the central controller responsible for coordinating all assessment modules.

Technology Stack

- FastAPI
- Python
- SQLAlchemy
- Pydantic
- PostgreSQL

Backend Responsibilities

- Handle API requests
- Execute scans
- Manage assessment modules
- Store assessment results
- Generate reports
- Maintain logs
- Provide dashboard statistics

---

# 5. Assessment Engine

The Assessment Engine is the core of the application.

Modules

Host Discovery Module

- Ping Sweep
- ARP Discovery
- Live Host Detection

Port Scanning Module

- TCP SYN Scan
- UDP Scan
- Full Port Scan
- Aggressive Scan

Service Enumeration Module

- Banner Grabbing
- Version Detection
- OS Detection

Vulnerability Assessment Module

- Nessus Integration
- OpenVAS Integration
- CVE Detection
- Risk Scoring

CVE Intelligence Module

- CVSS
- CWE
- MITRE ATT&CK
- Exploit Availability

Exploitation Module

- Metasploit Integration
- Session Management
- Evidence Collection

Packet Analysis Module

- PCAP Analysis
- Protocol Statistics
- TCP Streams
- Packet Inspection

Reporting Module

- HTML Reports
- PDF Reports
- Markdown Reports

---

# 6. Database Design

Primary Tables

Users

Hosts

OperatingSystems

Ports

Services

Scans

Vulnerabilities

CVEs

Exploits

Reports

Logs

Settings

Relationships

One Host

↓

Many Services

↓

Many Vulnerabilities

↓

Many Exploits

↓

Many Reports

---

# 7. API Design

Host APIs

GET /hosts

GET /hosts/{id}

POST /hosts/discover

Scan APIs

POST /scan/start

GET /scan/status

GET /scan/history

Port APIs

GET /ports

GET /ports/{host}

Service APIs

GET /services

Vulnerability APIs

GET /vulnerabilities

GET /vulnerabilities/{host}

Exploitation APIs

POST /exploit

GET /sessions

Packet APIs

GET /packets

GET /captures

Report APIs

POST /report/generate

GET /reports

GET /reports/{id}

Dashboard APIs

GET /dashboard

GET /statistics

---

# 8. Security Design

The application follows secure software development principles.

Security Measures

- Input Validation
- Exception Handling
- Secure API Design
- Structured Logging
- Authentication (Optional)
- Authorization (Optional)
- Parameter Validation
- Safe File Handling

All penetration testing activities are limited to the isolated laboratory environment.

---

# 9. Virtual Laboratory

Attacker

Kali Linux

Targets

Metasploitable2

Windows 7

Ubuntu Server (Optional)

Network

Host-Only Adapter

or

Internal Network

---

# 10. Data Flow

User

↓

Dashboard

↓

FastAPI

↓

Assessment Engine

↓

Nmap

↓

Nessus/OpenVAS

↓

Metasploit

↓

Wireshark

↓

Database

↓

Dashboard

↓

Professional Report

---

# 11. Logging Strategy

The application records

- Scan Start Time
- Scan Completion
- Errors
- Vulnerabilities
- Exploitation Attempts
- Packet Analysis
- Report Generation

Logs are stored in the database and exported when required.

---

# 12. Scalability

Future enhancements

- Active Directory Support
- LDAP Enumeration
- BloodHound Integration
- Docker Deployment
- Multi-user Authentication
- Scheduled Assessments
- Threat Intelligence Integration
- Cloud Asset Assessment

---

# 13. Design Principles

- Modular Architecture
- Separation of Concerns
- API-first Development
- Maintainable Code
- Reusable Components
- Professional Documentation
- Secure Development Practices

---

End of System Design