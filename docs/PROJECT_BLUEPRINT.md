# Network VAPT Platform — Project Blueprint

**Version:** 1.0.0  
**Project Type:** Full-Stack Cybersecurity Platform  
**Category:** Network Security / Penetration Testing  
**Development Methodology:** Incremental Phase-Wise Development  
**Target Platform:** Kali Linux + VirtualBox/VMware Lab  
**Primary Language:** Python  
**Frontend:** React + TypeScript + Tailwind CSS  
**Backend:** FastAPI + Python  
**Database:** PostgreSQL  

---

## 1. Project Overview

The Network VAPT Platform is a full-stack cybersecurity web application that automates the complete internal network penetration testing lifecycle. It integrates industry-standard tools — Nmap, Nessus/OpenVAS, Metasploit Framework, and Wireshark — into a unified orchestration layer with a professional React dashboard.

Instead of executing security tools manually from the command line, users manage the entire assessment workflow from a single web interface: host discovery, port scanning, service enumeration, vulnerability assessment, CVE intelligence, controlled exploitation, privilege escalation, lateral movement, packet analysis, and report generation.

**Purpose:** Educational, research, and authorised penetration testing only.

---

## 2. Problem Statement

Most cybersecurity learners and professionals execute tools like Nmap, Nessus, and Metasploit individually from the command line. While each tool is powerful, there is no unified workflow that:

- Orchestrates the complete VAPT lifecycle from a single interface
- Correlates findings across tools (e.g., CVE → Metasploit module mapping)
- Presents results through an interactive, visual dashboard
- Generates professional multi-format reports automatically
- Demonstrates full-stack software engineering skills alongside security expertise

This project bridges that gap by building an integrated penetration testing platform that automates the assessment process while presenting results through a polished web interface.

---

## 3. Aim

To assess the security posture of a simulated internal network by identifying live hosts, open ports, running services, and exploitable vulnerabilities, followed by controlled exploitation to demonstrate real-world attack paths — all orchestrated through a professional full-stack web application.

---

## 4. Objectives

1. Build an isolated virtual lab with Kali Linux, Metasploitable2, Windows 7, and Ubuntu Server.
2. Discover all live hosts on the internal network.
3. Perform TCP SYN and UDP port scanning.
4. Enumerate running services with version detection.
5. Detect operating systems remotely.
6. Perform vulnerability assessment using Nessus/OpenVAS.
7. Map discovered vulnerabilities to CVEs with CVSS scoring.
8. Correlate CVEs with available Metasploit exploit modules.
9. Demonstrate controlled exploit verification within the isolated lab.
10. Perform privilege escalation on compromised targets.
11. Demonstrate lateral movement across the network.
12. Capture and analyse network traffic using Wireshark.
13. Generate professional HTML, PDF, and Markdown VAPT reports.
14. Provide an interactive dashboard with real-time visualisations.

---

## 5. Scope

### Included
- Internal network discovery and assessment
- TCP/UDP port scanning and OS fingerprinting
- Service enumeration and banner grabbing
- Automated vulnerability assessment (Nessus/OpenVAS)
- CVE/CVSS/CWE mapping and intelligence
- Metasploit module correlation and controlled exploitation
- Privilege escalation and lateral movement demonstration
- PCAP capture and protocol analysis
- Executive and technical report generation (HTML, PDF, MD)
- Interactive React dashboard with charts and network topology

### Excluded
- Internet-wide scanning or external assessment
- Cloud infrastructure assessment
- Wireless network attacks
- Social engineering
- Denial-of-service attacks
- Testing systems without explicit authorisation
- Production deployment outside isolated lab

---

## 6. Ethical Statement

This platform is designed exclusively for educational and authorised security assessment purposes. All scanning and exploitation activities are confined to intentionally vulnerable virtual machines running inside an isolated laboratory network. No testing will be performed against public systems or systems without explicit written authorisation.

---

## 7. Technology Stack

| Layer          | Technology                          |
|----------------|-------------------------------------|
| Frontend       | React 18, TypeScript, Tailwind CSS  |
| Charts         | Recharts                            |
| HTTP Client    | Axios                               |
| Routing        | React Router v6                     |
| Backend        | FastAPI, Python 3.11+               |
| ORM            | SQLAlchemy 2.0                      |
| Validation     | Pydantic v2                         |
| Templates      | Jinja2                              |
| Database       | PostgreSQL 16                       |
| Security Tools | Nmap, Nessus/OpenVAS, Metasploit, Wireshark |
| Virtualisation | VirtualBox / VMware Workstation     |
| Version Control| Git + GitHub                        |

---

## 8. Lab Environment

| Role      | Machine            | IP Range         | Purpose                        |
|-----------|--------------------|------------------|--------------------------------|
| Attacker  | Kali Linux         | 192.168.56.10    | Runs the platform + tools      |
| Target 1  | Metasploitable2    | 192.168.56.20    | Vulnerable Linux target        |
| Target 2  | Windows 7 (unpatched) | 192.168.56.30 | Vulnerable Windows target      |
| Target 3  | Ubuntu Server      | 192.168.56.40    | Additional Linux target (opt.) |

**Network Type:** Host-Only Adapter (VirtualBox) or Internal Network (VMware)  
**Subnet:** 192.168.56.0/24

---

## 9. Architecture Overview

```
                ┌──────────────┐
                │    User      │
                │  (Browser)   │
                └──────┬───────┘
                       │ HTTPS
                ┌──────▼───────┐
                │   React UI   │
                │  Dashboard   │
                └──────┬───────┘
                       │ REST API
                ┌──────▼───────┐
                │   FastAPI    │
                │   Backend    │
                └──────┬───────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
    ┌─────▼─────┐ ┌───▼────┐ ┌───▼──────┐
    │Assessment │ │PostgreSQL│ │ Report   │
    │  Engine   │ │Database │ │ Generator │
    └─────┬─────┘ └────────┘ └──────────┘
          │
    ┌─────┼─────┬──────┬──────┐
    ▼     ▼     ▼      ▼      ▼
  Nmap  Nessus  MSF   Tshark  Other
              (OpenVAS)       Tools
          │
    ┌─────▼─────┐
    │  Virtual  │
    │  Lab Net  │
    │192.168.56.0/24│
    └───────────┘
```

---

## 10. Core Modules

| Module                  | Description                                      |
|-------------------------|--------------------------------------------------|
| Host Discovery          | Ping sweep, ARP discovery, live host detection   |
| Port Scanner            | TCP SYN, UDP, full connect, version detection    |
| Service Enumeration     | Banner grabbing, service fingerprinting, OS detection |
| Vulnerability Assessment| Nessus/OpenVAS integration, CVE discovery        |
| CVE Intelligence        | CVSS/CWE mapping, exploit availability lookup    |
| Exploitation Engine     | Metasploit integration, session management       |
| Privilege Escalation    | Local enum, kernel exploit matching, automated PE |
| Lateral Movement        | Network pivoting, credential reuse, target enum  |
| Packet Analysis         | PCAP analysis, protocol stats, TCP stream view   |
| Report Generator        | HTML/PDF/Markdown report generation              |
| Dashboard               | Statistics, charts, network topology, risk matrix |

---

## 11. Deliverables Summary

- Full-stack web application (React + FastAPI + PostgreSQL)
- Working React dashboard with real-time visualisations
- Automated host discovery, port scanning, service enumeration
- Vulnerability assessment with CVE/CVSS/CWE intelligence
- Controlled exploitation via Metasploit integration
- Privilege escalation and lateral movement demonstrations
- Packet capture and protocol analysis
- Professional reports (HTML, PDF, Markdown)
- Complete documentation (architecture, API, user guide)
- GitHub-ready repository with CI/CD workflows
- Resume-ready enterprise-grade cybersecurity project

---

*End of Project Blueprint*
