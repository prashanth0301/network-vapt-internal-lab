# Network VAPT Platform — Development Plan

**Version:** 1.0.0  
**Methodology:** Incremental Phase-Wise Development  

---

## Development Workflow

Each phase follows the same lifecycle:

1. **Plan** — Define objectives and deliverables
2. **Develop** — Build the code
3. **Test** — Verify correctness
4. **Document** — Update docs + README
5. **Screenshots** — Capture visual evidence
6. **Git Commit** — Commit with descriptive message

A phase is considered complete only when all of the above steps are done.

---

## Phase 0 — Project Planning

**Status:** ✅ Current Phase

| Detail | Description |
|--------|-------------|
| **Objectives** | Define architecture, select tech stack, design folder structure, plan APIs, design database, create documentation |
| **Deliverables** | `docs/PROJECT_BLUEPRINT.md`, `docs/SYSTEM_DESIGN.md`, `docs/DEVELOPMENT_PLAN.md`, `README.md`, `.gitignore`, `LICENSE` |

---

## Phase 1 — Virtual Lab Setup

| Detail | Description |
|--------|-------------|
| **Objectives** | Install VirtualBox/VMware, configure Host-Only Network, install Kali Linux, install Metasploitable2, install Windows 7 (unpatched), install Ubuntu Server (optional), verify connectivity |
| **Deliverables** | Working lab, network diagram, IP address table, connectivity screenshots |

---

## Phase 2 — Backend Foundation

| Detail | Description |
|--------|-------------|
| **Objectives** | Create FastAPI project, configure logging, configure database, create models, create API structure, configure environment, set up Alembic migrations |
| **Deliverables** | Backend skeleton, API documentation (Swagger/ReDoc), database migrations, environment configuration |

---

## Phase 3 — Frontend Foundation

| Detail | Description |
|--------|-------------|
| **Objectives** | Create React project with Vite, configure TypeScript, set up Tailwind CSS, configure routing (React Router), create layout components (sidebar, header, main), configure Axios API client, implement theme/design system |
| **Deliverables** | React app skeleton with routing, navigation, layout, and API client |

---

## Phase 4 — Dashboard Development

| Detail | Description |
|--------|-------------|
| **Objectives** | Build dashboard page, host summary cards, scan summary widgets, risk distribution pie chart, recent scans table, network topology placeholder, statistics API endpoint |
| **Deliverables** | Professional interactive dashboard |

---

## Phase 5 — Host Discovery

| Detail | Description |
|--------|-------------|
| **Objectives** | Implement ping sweep, ARP discovery, live host detection, parse Nmap output, store host data, host list/detail pages |
| **Deliverables** | Host inventory with discovery API and UI |

---

## Phase 6 — Port Scanner

| Detail | Description |
|--------|-------------|
| **Objectives** | Implement TCP SYN scan, UDP scan, full port scan, OS detection, version detection (`-sV`), parse Nmap XML, port results page with filtering |
| **Deliverables** | Port inventory with scan API and interactive UI |

---

## Phase 7 — Service Enumeration

| Detail | Description |
|--------|-------------|
| **Objectives** | Implement banner grabbing, service fingerprinting, OS fingerprint parsing, service version correlation, service details page |
| **Deliverables** | Service inventory with enumeration API and UI |

---

## Phase 8 — Vulnerability Assessment

| Detail | Description |
|--------|-------------|
| **Objectives** | Integrate Nessus REST API, integrate OpenVAS GMP, create scan config, launch assessment, poll and download results, parse findings, store vulnerabilities |
| **Deliverables** | Vulnerability inventory with assessment API and UI |

---

## Phase 9 — CVE Intelligence

| Detail | Description |
|--------|-------------|
| **Objectives** | Map findings to CVEs, assign CVSS scores, map CWE categories, check exploit availability (Metasploit/NVD), MITRE ATT&CK mapping, CVE detail page with exploit matches |
| **Deliverables** | CVE intelligence dashboard with exploit correlation |

---

## Phase 10 — Exploit Verification

| Detail | Description |
|--------|-------------|
| **Objectives** | Integrate Metasploit RPC, list matching modules, configure payloads, execute controlled exploits, capture evidence (screenshots, console output), manage sessions, exploit browser UI |
| **Deliverables** | Controlled exploitation with Metasploit integration and session management |

---

## Phase 11 — Privilege Escalation

| Detail | Description |
|--------|-------------|
| **Objectives** | Local enumeration scripts, kernel version matching, suggest PE exploits, automate known PE paths, document escalation chain |
| **Deliverables** | Privilege escalation demonstration with evidence |

---

## Phase 12 — Lateral Movement

| Detail | Description |
|--------|-------------|
| **Objectives** | Network pivoting via compromised host, target enumeration from pivot point, credential harvesting and reuse, attack path visualisation |
| **Deliverables** | Lateral movement demonstration with attack path documentation |

---

## Phase 13 — Packet Analysis

| Detail | Description |
|--------|-------------|
| **Objectives** | Capture traffic during assessment, protocol analysis with tshark, TCP stream reassembly, packet inspection UI, PCAP file management |
| **Deliverables** | Wireshark/tshark analysis integrated into the dashboard |

---

## Phase 14 — Report Generation

| Detail | Description |
|--------|-------------|
| **Objectives** | Executive summary report, technical findings report, risk matrix, remediation recommendations, HTML template (Jinja2), PDF generation (WeasyPrint), Markdown export |
| **Deliverables** | Professional reports in HTML, PDF, and Markdown formats |

---

## Phase 15 — Testing

| Detail | Description |
|--------|-------------|
| **Objectives** | Unit tests for all services, integration tests for API endpoints, frontend component tests, API contract tests, end-to-end workflow test |
| **Deliverables** | Test suite with pytest (backend) and Vitest (frontend), coverage report |

---

## Phase 16 — Documentation

| Detail | Description |
|--------|-------------|
| **Objectives** | Complete README with badges, installation guide, user guide, API documentation, architecture diagrams, contribution guide |
| **Deliverables** | Comprehensive project documentation |

---

## Phase 17 — GitHub Release

| Detail | Description |
|--------|-------------|
| **Objectives** | Final code review, version tag (v1.0.0), release notes, CI/CD workflow (GitHub Actions), repository cleanup, README finalisation |
| **Deliverables** | GitHub Release v1.0.0 with release artifacts |

---

## Git Workflow

Every completed phase follows:

```bash
git add .
git commit -m "Phase <N>: <description>"
git tag -a "v1.0.0-phase<N>" -m "Phase <N> completed"
```

### Example Commits
```
Phase 0: Project Planning — architecture, design docs, structure
Phase 1: Virtual Lab Setup — Kali, Metasploitable2, Windows 7
Phase 2: Backend Foundation — FastAPI skeleton, models, database
Phase 3: Frontend Foundation — React, TypeScript, Tailwind setup
Phase 4: Dashboard — Statistics, charts, summary widgets
Phase 5: Host Discovery — Nmap ping sweep, live host detection
Phase 6: Port Scanner — TCP/UDP scanning, OS detection
Phase 7: Service Enumeration — Banner grabbing, version detection
Phase 8: Vulnerability Assessment — Nessus/OpenVAS integration
Phase 9: CVE Intelligence — CVSS, CWE, exploit correlation
Phase 10: Exploit Verification — Metasploit RPC, sessions
Phase 11: Privilege Escalation — Local enum, kernel exploits
Phase 12: Lateral Movement — Pivoting, credential reuse
Phase 13: Packet Analysis — TShark, protocol stats, TCP streams
Phase 14: Report Generation — HTML, PDF, Markdown reports
Phase 15: Testing — pytest, Vitest, coverage
Phase 16: Documentation — README, guides, diagrams
Phase 17: GitHub Release — v1.0.0 tag, CI/CD, release notes
```

---

## Success Criteria

The project is complete when it demonstrates:

- Full-stack web application (React + FastAPI + PostgreSQL)
- Working React dashboard with real-time visualisations
- Automated network discovery and port scanning
- Service enumeration with version detection
- Vulnerability assessment with CVE/CVSS/CWE intelligence
- Controlled exploit verification via Metasploit
- Privilege escalation and lateral movement demonstrations
- Packet capture and protocol analysis
- Professional multi-format report generation
- Complete documentation
- GitHub-ready repository with CI/CD

---

*End of Development Plan*
