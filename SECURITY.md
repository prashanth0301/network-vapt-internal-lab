# Security Policy

The **Network VAPT Platform** is designed for internal network security assessments and penetration-testing lab work. The security of the platform itself matters as much as the security it helps you evaluate — this policy explains how vulnerabilities are handled, what is covered, and what protections are already in place.

---

## Supported Versions

The following version is currently supported with security fixes:

| Version | Supported |
|---|---|
| 1.0 (current) | ✅ Supported |

Earlier pre-release snapshots and feature branches are **not** supported and should not be used in any environment that processes real or sensitive data. Security fixes are delivered on the `main` branch and released as part of the next patch or minor version.

---

## Reporting a Vulnerability

Please report security issues **privately** — never in public issues, discussions, pull requests, or commit messages.

### How to report

1. Open a **private security report** via the repository's **Security Advisories** page (GitHub: *Security → Report a vulnerability*), or
2. Contact the maintainers directly through a private channel (email or private message), clearly marked as a security report.

> **Do not publicly disclose a vulnerability before a fix is available.** Publicly describing an unpatched issue gives attackers a roadmap and can put deployments at risk.

### What to include

Provide as much detail as possible to help us reproduce and fix the issue quickly:

- **Summary** — what the vulnerability is and the affected component/endpoint
- **Severity assessment** — your estimate of impact (and CVSS score if you have one)
- **Reproduction steps** — minimal, numbered steps, including the exact requests or UI actions
- **Proof of concept** — payloads, snippets, or screenshots demonstrating the issue
- **Logs** — relevant excerpts from `backend/logs/vapt.log` or Docker logs, if possible
- **Environment** — OS, Docker/Python/Node versions, and deployment mode (Docker Compose vs. local dev)

You should receive an acknowledgment within a few days. We will investigate, confirm the issue, and work with you on a fix and disclosure timeline before publishing anything.

---

## Scope

The following components are in scope for security reporting:

| Component | Notes |
|---|---|
| **Authentication** | Login/logout, token lifecycle, password reset, user management |
| **JWT** | Access/refresh token signing (HS256), validation, expiration, and rotation logic |
| **RBAC** | Role definitions, granular permissions, and permission enforcement on endpoints |
| **Packet Capture** | Live capture, PCAP upload, interface enumeration, and capture storage |
| **Reports** | Report generation, storage, download, rename, and delete flows |
| **Assessment Engine** | The 6-stage pipeline (host discovery → exploit verification), scan execution, and artifact handling |
| **Database** | Schema, query construction, and data storage (PostgreSQL) |
| **Docker Deployment** | `docker/docker-compose.yml`, Dockerfiles, environment configuration, and container isolation |

Anything that processes, stores, or exposes assessment data — hosts, ports, services, vulnerabilities, CVEs, exploits, captures, reports, audit logs, and user records — is in scope.

---

## Security Features

The following protections are implemented in Version 1.0:

- **JWT authentication** — short-lived HS256 access tokens with role claims, rotating refresh tokens, and 401-driven redirects to login on the frontend.
- **Router-level authentication** — every API router except `/health` and the authentication endpoints enforces `Depends(get_current_user)` at the router level, so unauthenticated requests are rejected before reaching any handler.
- **Role-Based Access Control (RBAC)** — three roles (`administrator`, `security_analyst`, `viewer`) with nine granular permissions, enforced per endpoint via `require_permissions([...])`.
- **Password hashing** — bcrypt with per-user salts, minimum-length validation, and last-administrator protection on role/status changes.
- **Audit logging** — every significant action (login, logout, user management, settings changes, scan and report operations) is recorded with actor, action, resource, IP address, user agent, status, and details.
- **ORM parameterized queries** — all database access goes through SQLAlchemy ORM/query builder; no string-interpolated SQL.
- **Input validation** — Pydantic v2 request/response validation and sanitization on all endpoints.
- **Report access control** — report listing, generation, download, rename, and delete are authentication- and permission-gated.
- **Protected exploit verification** — exploit lookup and Metasploit execution endpoints require authentication (and the relevant permission).
- **Protected packet capture** — capture start/stop, interface enumeration, upload, and packet retrieval all require authentication.
- **Minimal container exposure** — only the frontend and backend ports are published; the database is reachable only on the internal Docker network.
- **Non-enumerable identifiers** — UUID primary keys across all tables.

---

## Out of Scope

The following are **not** production deployments and are explicitly out of scope for security reports:

- **Local development credentials** — default secrets and accounts such as `admin` / `Admin@123`, the default `JWT_SECRET`, and `.env` default values are development conveniences, not production configurations.
- **Lab environments** — deliberately vulnerable lab targets shipped with the project (e.g., the vulnerable Apache, FTP, and Metasploitable-style targets in `docker/lab/`) exist for training purposes; their weaknesses are intentional.
- **Test data and fixtures** — sample captures, scanner XML fixtures, and seeded records in `backend/tests/` and `artifacts/`.
- **Docker development configuration** — the development compose setup, exposed debug endpoints, and relaxed defaults are not hardened deployment profiles.

If you deploy the platform in a shared or production-like environment, you are responsible for applying production hardening first: unique secrets, rotated admin credentials, least-privilege roles, host firewall rules, and network isolation.

---

## Responsible Disclosure

We ask that all researchers and reporters follow coordinated disclosure:

1. Report the issue privately (see [Reporting a Vulnerability](#reporting-a-vulnerability)).
2. Allow a reasonable time window for investigation and remediation before publishing any details.
3. After a fix is released, publish findings in a coordinated manner so users can upgrade before technical details go public.
4. Never exploit a confirmed vulnerability beyond what is necessary to demonstrate it, and never access data other than your own.

We will acknowledge valid reports, keep reporters informed of progress, and credit them in the fix and release notes (with consent).

---

## Acknowledgements

We are grateful to every security researcher, penetration tester, and contributor who takes the time to examine the platform and report issues responsibly. Your reports help make the Network VAPT Platform safer for everyone using it.

Thank you for helping improve project security.
