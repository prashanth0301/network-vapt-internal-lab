# Network VAPT Platform — Project Plan

## Project Identity

| Field | Value |
|-------|-------|
| Title | Network Vulnerability Assessment & Penetration Testing Platform |
| Type | Full-Stack Cybersecurity Web Application |
| Methodology | Incremental Phase-Wise Development |
| Target | Isolated Virtual Internal Network Lab |

---

## Problem Statement

Cybersecurity learners and professionals execute tools like Nmap, Nessus, Metasploit, and Wireshark individually from the command line. This fragmented workflow lacks:

- A unified orchestration layer
- Centralized visualization of findings
- Automated correlation between vulnerabilities and exploits
- Professional report generation in multiple formats
- A resume-ready full-stack project demonstrating both security and software engineering skills

---

## Solution

A full-stack web platform that:

1. Orchestrates the complete VAPT lifecycle from a single React dashboard
2. Integrates Nmap, Nessus/OpenVAS, Metasploit, and Wireshark under one backend
3. Automates host discovery → port scanning → service enumeration → vulnerability assessment → CVE correlation → exploit mapping → controlled exploitation → packet analysis → report generation
4. Stores all results in PostgreSQL for querying, visualization, and historical comparison
5. Generates professional HTML, PDF, and Markdown reports

---

## Core Principles

- **Integration, not replacement** — The platform wraps existing security tools; it does not reimplement them
- **Safety-first** — All testing is restricted to an isolated virtual lab (Host-Only Network)
- **Modular architecture** — Each assessment module is independent and testable
- **API-first design** — Every feature is accessible via REST API
- **Educational value** — Built to demonstrate both cybersecurity and software engineering competence

---

## Technology Stack

### Frontend
- React 18+ with TypeScript
- Tailwind CSS for styling
- React Router for navigation
- Axios for HTTP communication
- Recharts for data visualization

### Backend
- FastAPI (Python 3.11+)
- SQLAlchemy ORM
- Pydantic for validation
- Jinja2 for HTML report templates
- Uvicorn as ASGI server

### Database
- PostgreSQL 15+

### Security Tools
- Nmap (network discovery & enumeration)
- Nessus / OpenVAS (vulnerability scanning)
- Metasploit Framework (exploit verification)
- Wireshark / tshark (packet capture & analysis)

### Virtualization
- VirtualBox 7+ or VMware Workstation

### Version Control
- Git + GitHub

---

## Virtual Lab Topology

```
┌─────────────────────────────────────────────────────────┐
│                  Host-Only Network                       │
│                   192.168.56.0/24                        │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │  Kali Linux   │  │Metasploitable│  │  Windows 7    │   │
│  │  (Attacker)   │  │     2        │  │ (Unpatched)   │   │
│  │ 192.168.56.10 │  │192.168.56.20 │  │192.168.56.30  │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                          │
│  ┌──────────────┐                                        │
│  │Ubuntu Server │  (Optional)                            │
│  │192.168.56.40 │                                        │
│  └──────────────┘                                        │
└─────────────────────────────────────────────────────────┘
```

---

## Deliverables Checklist

| # | Deliverable | Phase |
|---|-------------|-------|
| 1 | Project Plan, Architecture, API Spec, DB Schema | 0 |
| 2 | Virtual Lab with all VMs and verified connectivity | 1 |
| 3 | FastAPI backend with DB, logging, error handling | 2 |
| 4 | React frontend with routing, layout, theme | 3 |
| 5 | Dashboard with charts, stats, risk summary | 4 |
| 6 | Host Discovery (Nmap ping sweep, ARP) | 5 |
| 7 | Port Scanner (TCP, UDP, version, OS) | 6 |
| 8 | Service Enumeration (banner grab, version detect) | 7 |
| 9 | Vulnerability Assessment (Nessus/OpenVAS) | 8 |
| 10 | CVE Intelligence (CVSS, CWE, exploit mapping) | 9 |
| 11 | Exploit Verification (Metasploit integration) | 10 |
| 12 | Privilege Escalation (local enum, exploit) | 11 |
| 13 | Lateral Movement (pivoting, target enum) | 12 |
| 14 | Packet Analysis (PCAP, protocol stats, streams) | 13 |
| 15 | Report Generation (HTML, PDF, Markdown) | 14 |
| 16 | Testing (unit, integration, API, UI) | 15 |
| 17 | Documentation (guides, API docs, inline) | 16 |
| 18 | GitHub Release (tag, notes, cleanup) | 17 |

---

## Success Criteria

The project is complete when:

- [ ] React dashboard displays live hosts, open ports, services, vulnerabilities, and CVEs
- [ ] FastAPI backend orchestrates all tools and stores results in PostgreSQL
- [ ] Host discovery identifies all VMs in the lab
- [ ] Port scanner detects TCP/UDP ports with service versions
- [ ] Vulnerability assessment finds CVEs with risk scores
- [ ] CVEs are correlated with Metasploit modules
- [ ] Controlled exploits are verified (screenshots captured)
- [ ] Privilege escalation is demonstrated
- [ ] Lateral movement is demonstrated
- [ ] Wireshark captures are analysed (protocol stats, TCP streams)
- [ ] HTML, PDF, and Markdown reports are generated
- [ ] Repository is GitHub-ready with complete documentation

---

## Ethical & Legal Statement

This project operates **exclusively** within an isolated virtual network. No testing is performed against systems without explicit authorization. All vulnerable machines (Metasploitable2, Windows 7) are intentionally designed for security education. The platform is intended for:

- Cybersecurity education and training
- Authorized penetration testing engagements
- Academic research (B.Tech final year projects)
- Interview demonstrations and resume portfolios

---

*End of Project Plan*
