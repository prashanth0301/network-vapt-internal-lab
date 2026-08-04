# User Guide

## Getting Started

### Logging In

1. Navigate to `http://localhost:5173`
2. Enter your username and password
3. Optionally check **Remember Me** for extended sessions
4. Click **Sign In**

Default administrator credentials: `admin` / `Admin@123`

### First-Time Workflow

1. **Set up the workspace** — Navigate to the Workspace page to create your first assessment
2. **Run a full assessment** — The platform will execute all 6 pipeline stages automatically
3. **Review results** — Check the Dashboard for an overview, then drill into specific sections
4. **Generate reports** — Export findings as Executive, Technical, or Compliance reports

---

## Navigation

The sidebar provides access to all platform sections:

### Operations

| Page | Path | Description |
|---|---|---|
| **Dashboard** | `/` | Security overview with charts and KPIs |
| **Workspace** | `/workspace` | Quick-launch assessment creation |
| **Hosts** | `/hosts` | Discovered network hosts |
| **Port Scanner** | `/scanning` | Port scanning orchestration |
| **Services** | `/services` | Detected network services |
| **Vulnerabilities** | `/vulnerabilities` | Identified vulnerabilities |
| **CVE Intelligence** | `/cves` | CVE database and intelligence |
| **History** | `/history` | Past assessment records |
| **Exploit Verification** | `/exploits` | Exploit matching and verification |
| **Exploitation** | `/exploitation` | Exploit execution and tracking |
| **Packet Analysis** | `/packets` | Packet capture and analysis |
| **Reports** | `/reports` | Report generation and management |

### Administration (Administrator only)

| Page | Path | Description |
|---|---|---|
| **User Management** | `/users` | Create, edit, and manage user accounts |
| **Settings** | `/settings` | Application configuration |
| **Audit Logs** | `/audit-logs` | Security audit trail |

---

## Dashboard

The dashboard is the main landing page. It displays:

### Assessment Selector

The dropdown at the top-right lets you filter all dashboard widgets by a specific assessment. Selecting an assessment updates every widget immediately:

- Risk Score
- Critical vulnerability count
- Exploit count
- Total vulnerabilities
- Severity distribution chart
- Vulnerability trend chart
- Top open ports chart
- Service distribution chart
- Top vulnerable hosts
- Recent reports
- Scan duration statistics
- Activity timeline

Select **All assessments** to see the global aggregate view.

### KPI Cards

| Card | Shows |
|---|---|
| **Risk Score** | Weighted severity score (0–100) with level badge |
| **Critical Vulnerabilities** | Count of Critical-severity findings |
| **Exploits Available** | Number of CVEs with known public exploits |
| **Total Vulnerabilities** | All findings with host and port counts |

### Charts

- **Severity Distribution** — Donut chart of Critical/High/Medium/Low/Info findings
- **Vulnerability Trend** — Area chart of findings over the last 14 days
- **Top Open Ports** — Horizontal bar chart of most common open ports
- **Service Distribution** — Bar chart of top services by exposure
- **Top Vulnerable Hosts** — Bar chart of hosts ranked by finding count
- **Scan Duration Statistics** — Average, fastest, and slowest scan times
- **Activity Timeline** — Recent platform events (logins, scans, reports)

---

## Assessment Workflow

### Creating an Assessment

**Via Workspace (Quick Launch):**

1. Navigate to **Workspace**
2. The page automatically creates and starts a new Full Assessment
3. Real-time progress is shown for each pipeline stage

**Via API:**

1. `POST /api/v1/assessments` with target and scan type
2. `POST /api/v1/assessments/{id}/start` to begin execution

### Pipeline Stages

Each assessment runs through 6 sequential stages:

| Stage | Description | Duration |
|---|---|---|
| 1. **Host Discovery** | Ping sweep to identify live hosts | Fast |
| 2. **Port Scan** | Nmap SYN scan for open ports | Moderate |
| 3. **Service Intelligence** | Service detection, version identification, banner grabbing | Moderate |
| 4. **Vulnerability Assessment** | Nmap/OpenVAS vulnerability scanning | Slow |
| 5. **CVE Intelligence** | NVD enrichment, EPSS scoring, KEV lookup | Moderate |
| 6. **Exploit Verification** | Metasploit module matching and verification | Slow |

Progress is displayed as a percentage and per-stage status bar.

### Viewing Results

- **Dashboard** — High-level overview across all assessments or filtered by one
- **History** — List of all assessments with status, duration, severity summary
- **Assessment Overview** (`/history/{id}`) — Detailed view of a single assessment with all metrics
- **Host Details** (`/hosts/{id}`) — 11-tab deep dive into a specific host

---

## Host Details

Click any host IP to access the detailed view with 11 tabs:

| Tab | Contents |
|---|---|
| **Overview** | IP, hostname, OS, MAC, status, latency |
| **OS** | Operating system detection details and accuracy |
| **Ports** | All discovered ports with state and protocol |
| **Services** | Detected services with product, version, category |
| **Banners** | Raw service banners captured during scanning |
| **Vulnerabilities** | All vulnerabilities with severity and CVSS scores |
| **CVEs** | Associated CVEs with CVSS, EPSS, KEV status |
| **Exploits** | Matched exploits with provider, rank, and status |
| **Evidence** | Raw scanner output and plugin evidence |
| **Scan History** | Previous scans against this host |
| **Reports** | Reports associated with this host |

---

## Scanning

### Port Scanner

1. Navigate to **Port Scanner**
2. Enter a target IP or CIDR range
3. Select a scan profile (Quick, Standard, Deep, Custom)
4. Click **Start Scan**
5. Monitor progress in real-time

### Vulnerability Scan

1. Navigate to **Vulnerabilities**
2. Click **Start Scan**
3. Select target and scan profile
4. Results appear in the vulnerability table as they are discovered

---

## Exploit Verification

### Viewing Exploits

Navigate to **Exploit Verification** to see all matched exploits across assessments. The table shows:

- Exploit name and module
- Source (Metasploit, Exploit-DB, GitHub, PacketStorm)
- Associated CVE
- Remote/Local classification
- Authentication requirements
- Rank (excellent, great, good, normal, low)
- Status (identified, pending, running, completed, failed)

### Running Exploits

Navigate to **Exploitation** to interact with exploits:

1. Filter by status to find "identified" exploits
2. Click **Run** on a Metasploit exploit
3. The platform resolves the target host IP automatically
4. Execution status updates in real-time
5. Completed exploits appear in the Exploit History table

> **Note:** Exploit execution requires a running Metasploit RPC service configured via `MSF_RPC_HOST`, `MSF_RPC_PORT`, and `MSF_RPC_PASSWORD` environment variables.

---

## Reports

### Generating Reports

1. Navigate to **Reports**
2. Click **Generate Report**
3. Select:
   - **Type:** Executive, Technical, or Compliance
   - **Format:** JSON, HTML, or PDF
4. Click **Generate**

### Report Types

| Type | Audience | Contents |
|---|---|---|
| **Executive** | Management | Risk summary, key findings, recommendations |
| **Technical** | Engineers | Full vulnerability details, evidence, remediation steps |
| **Compliance** | Auditors | Mapped findings against compliance frameworks |

### Managing Reports

- **Download** — Click the download button to save the file
- **Rename** — Click the name to edit inline
- **Delete** — Click delete and confirm

---

## Packet Analysis

### Live Capture

1. Navigate to **Packet Analysis**
2. Select a network interface
3. Click **Start Capture**
4. Monitor packets in real-time
5. Click **Stop** when done

### Upload PCAP

1. Click **Upload PCAP**
2. Select a `.pcap` or `.pcapng` file
3. The file is parsed and analyzed automatically

### Analysis Views

- **Protocol Stats** — Distribution of protocols in the capture
- **Packets** — Individual packet list with search and filtering
- **Conversations** — Network conversations between hosts

---

## User Management

*Administrator role required.*

### Creating Users

1. Navigate to **User Management**
2. Click **Create User**
3. Fill in username, email, full name, role, and password
4. Click **Create**

### Role Assignment

| Role | Capabilities |
|---|---|
| **Administrator** | Full access to all features and settings |
| **Security Analyst** | Run scans, view/export reports, view audit logs |
| **Viewer** | View reports only |

### User Actions

- **Edit** — Update email and full name
- **Change Role** — Assign a different role
- **Activate/Deactivate** — Enable or disable the account
- **Reset Password** — Admin password reset
- **Delete** — Remove the user account (cannot delete self)

---

## Settings

*Administrator role required.*

### Configuration Tabs

| Tab | Settings |
|---|---|
| **General** | Application name, logo, default language |
| **Scanner** | Nmap path, scan profiles, timeouts |
| **Reporting** | Default format, templates, retention |
| **Security** | Session timeout, password policy, CORS |
| **System** | Docker status, database health, disk usage, memory |

### Actions

- **Save** — Apply setting changes
- **Reset to Defaults** — Restore all settings to factory defaults
- **Upload Logo** — Set a company logo for reports
- **System Info** — View detailed system diagnostics

---

## Audit Logs

*Administrator or Security Analyst role required.*

The audit log records every significant action on the platform:

- User logins and logouts
- Assessment creation and execution
- Report generation
- Settings changes
- User management actions

### Filtering

Use the filter bar to narrow results by:
- User
- Action type
- Status (success/failure)
- Date range

### Export

Click **Export CSV** or **Export JSON** to download the filtered audit trail.

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Esc` | Close modal/dialog |
| `Tab` | Navigate between form fields |
| `Enter` | Submit form |

---

## Troubleshooting

| Issue | Solution |
|---|---|
| Dashboard shows "Loading" forever | Check backend health: `curl http://localhost:8000/api/v1/health` |
| Scan stuck at a stage | Check scanner logs: `docker logs vapt-backend` |
| Exploit Run button disabled | Ensure the exploit is Metasploit-based and has status "identified" |
| Report generation fails | Verify the `reports/` directory is writable |
| Cannot create users | Ensure you are logged in as Administrator |
