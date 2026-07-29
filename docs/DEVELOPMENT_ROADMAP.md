# Development Roadmap

## Phase Timeline

| Phase | Name | Est. Effort | Dependencies |
|-------|------|-------------|--------------|
| 0 | Project Planning | 2 days | None |
| 1 | Virtual Lab Setup | 3 days | Phase 0 |
| 2 | Backend Foundation | 3 days | Phase 1 |
| 3 | Frontend Foundation | 3 days | Phase 2 |
| 4 | Dashboard | 2 days | Phase 3 |
| 5 | Host Discovery | 2 days | Phase 4 |
| 6 | Port Scanner | 2 days | Phase 5 |
| 7 | Service Enumeration | 1 day | Phase 6 |
| 8 | Vulnerability Assessment | 3 days | Phase 7 |
| 9 | CVE Intelligence | 2 days | Phase 8 |
| 10 | Exploit Verification | 3 days | Phase 9 |
| 11 | Privilege Escalation | 1 day | Phase 10 |
| 12 | Lateral Movement | 1 day | Phase 11 |
| 13 | Packet Analysis | 2 days | Phase 12 |
| 14 | Report Generation | 2 days | Phase 13 |
| 15 | Testing | 2 days | Phase 14 |
| 16 | Documentation | 2 days | Phase 15 |
| 17 | GitHub Release | 1 day | Phase 16 |

**Total**: ~33 working days

---

## Phase Breakdown

### Phase 0 — Project Planning
- Define architecture
- Design folder structure
- Plan API endpoints
- Design database schema
- Create documentation

### Phase 1 — Virtual Lab Setup
- Install VirtualBox
- Configure Host-Only Network
- Install Kali Linux
- Install Metasploitable 2
- Install Windows 7
- Verify connectivity

### Phase 2 — Backend Foundation
- FastAPI project scaffolding
- PostgreSQL connection
- SQLAlchemy models
- Pydantic schemas
- Logging configuration
- Error handling middleware
- Health check endpoint

### Phase 3 — Frontend Foundation
- React project scaffolding (Vite)
- TypeScript configuration
- Tailwind CSS setup
- React Router setup
- Axios API client
- Layout components (Navbar, Sidebar)
- Dark theme

### Phase 4 — Dashboard
- Dashboard page layout
- Stat cards (hosts, ports, vulns, exploits)
- Severity distribution chart (Recharts)
- Recent scans table
- API integration

### Phase 5 — Host Discovery
- Nmap ping sweep wrapper
- ARP discovery wrapper
- Host detection endpoint
- Store results in DB
- Frontend hosts page

### Phase 6 — Port Scanner
- TCP SYN scan wrapper
- UDP scan wrapper
- Service/version detection
- OS fingerprinting
- Frontend scan results page

### Phase 7 — Service Enumeration
- Banner grabbing
- Version detection
- Service inventory display
- Frontend services page

### Phase 8 — Vulnerability Assessment
- OpenVAS/Nessus integration
- Scan orchestration
- Results parsing
- Risk scoring
- Frontend vulnerabilities page

### Phase 9 — CVE Intelligence
- CVE lookup and enrichment
- CVSS scoring display
- CWE mapping
- Exploit availability detection
- Metasploit module correlation

### Phase 10 — Exploit Verification
- Metasploit RPC client
- Module search/selection
- Exploit execution
- Session management
- Evidence collection (screenshots)
- Frontend exploitation page

### Phase 11 — Privilege Escalation
- Local enumeration scripts
- Kernel exploit detection
- Exploit execution (e.g., Dirty Cow, MS10-059)
- Evidence documentation

### Phase 12 — Lateral Movement
- Network pivoting setup
- Target enumeration from compromised host
- Pass-the-hash (Windows)
- SSH key harvesting (Linux)
- Evidence documentation

### Phase 13 — Packet Analysis
- tshark PCAP capture
- Protocol statistics
- TCP stream reassembly
- Packet inspection
- Frontend packet analysis page

### Phase 14 — Report Generation
- Jinja2 HTML templates
- Executive summary
- Technical findings
- Risk matrix
- Recommendations
- PDF via WeasyPrint
- Markdown export

### Phase 15 — Testing
- Backend unit tests (pytest)
- API integration tests
- Frontend component tests
- End-to-end workflow tests
- Vulnerable machine verification

### Phase 16 — Documentation
- README with badges
- Installation guide
- User manual
- API documentation
- Architecture documentation
- Screenshot collection

### Phase 17 — GitHub Release
- Code cleanup
- Version tagging (v1.0.0)
- Release notes
- Repository finalization

---

## Key Milestones

| Milestone | Phase | Deliverable |
|-----------|-------|-------------|
| M1 | 1 | Working virtual lab with all VMs |
| M2 | 2 | Backend serves API with DB connected |
| M3 | 3 | Frontend renders with navigation |
| M4 | 4 | Dashboard shows real data |
| M5 | 7 | Full network enumeration complete |
| M6 | 9 | All CVEs mapped with exploit info |
| M7 | 10 | Controlled exploit succeeds |
| M8 | 14 | Professional report generated |
| M9 | 17 | v1.0.0 released on GitHub |

---

*End of Development Roadmap*
