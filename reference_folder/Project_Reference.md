# Network Vulnerability Assessment and Penetration Testing (Internal Network Lab)

# PROJECT BLUEPRINT

Version: 1.0
Project Type: Full Stack Cybersecurity Platform
Category: Network Security / Penetration Testing
Development Methodology: Incremental Phase-wise Development
Target Platform: Kali Linux + VirtualBox/VMware Lab
Primary Language: Python
Frontend: React
Backend: FastAPI

--------------------------------------------------------------------------------

# 1. Project Overview

The Network Vulnerability Assessment and Penetration Testing (Internal Network Lab)
is a full-stack cybersecurity platform developed to simulate a professional
internal penetration testing engagement within a controlled virtual laboratory.

The platform automates the complete internal network assessment lifecycle,
including network discovery, host enumeration, service identification,
vulnerability assessment, controlled exploitation, packet analysis and
professional report generation.

Instead of simply executing security tools manually, the project integrates
multiple industry-standard tools into one centralized dashboard, allowing users
to perform assessments, visualize findings and generate reports from a single
interface.

The project is intended for educational, research and authorised penetration
testing purposes only.

--------------------------------------------------------------------------------

# 2. Problem Statement

Most cybersecurity learners execute tools such as Nmap, Nessus and Metasploit
individually from the command line.

While these tools are powerful, they lack a unified workflow for beginners and
do not demonstrate software engineering skills.

This project aims to bridge that gap by building an integrated penetration
testing platform capable of automating the complete assessment process while
presenting results through an intuitive web interface.

--------------------------------------------------------------------------------

# 3. Aim

To assess the security posture of a simulated internal network by identifying
live hosts, open ports, running services and exploitable vulnerabilities,
followed by controlled exploitation to demonstrate real-world attack paths.

--------------------------------------------------------------------------------

# 4. Objectives

• Build an isolated penetration testing laboratory.
• Discover all live hosts.
• Perform TCP and UDP port scanning.
• Enumerate running services.
• Detect operating systems.
• Perform vulnerability assessments.
• Map vulnerabilities to CVEs.
• Correlate CVEs with Metasploit modules.
• Demonstrate controlled exploitation.
• Perform privilege escalation where applicable.
• Demonstrate lateral movement.
• Capture assessment traffic.
• Analyse packets.
• Generate professional reports.
• Provide an interactive dashboard.

--------------------------------------------------------------------------------

# 5. Scope

INCLUDED

✓ Internal Network Assessment
✓ Host Discovery
✓ Port Scanning
✓ Service Enumeration
✓ Vulnerability Assessment
✓ CVE Mapping
✓ Controlled Exploitation
✓ Packet Analysis
✓ Report Generation
✓ Dashboard
✓ Network Topology
✓ Professional Documentation

NOT INCLUDED

✗ Internet-wide scanning
✗ Cloud infrastructure
✗ Wireless attacks
✗ Social Engineering
✗ DoS attacks
✗ Testing systems without authorization

--------------------------------------------------------------------------------

# 6. Ethical Statement

This project will only assess intentionally vulnerable virtual machines running
inside an isolated laboratory network.

No testing will be performed against public systems or systems without explicit
authorization.

All exploitation activities are conducted solely for educational and defensive
security purposes.

--------------------------------------------------------------------------------

# 7. Technology Stack

Frontend
---------
React
TypeScript
Tailwind CSS
Axios
Recharts

Backend
--------
FastAPI
Python
SQLAlchemy
Pydantic
Jinja2

Database
---------
PostgreSQL

Security Tools
--------------
Nmap
Nessus / OpenVAS
Metasploit Framework
Wireshark

Virtualization
--------------
VirtualBox / VMware

Version Control
---------------
Git
GitHub

--------------------------------------------------------------------------------

# 8. Lab Environment

Attacker Machine

• Kali Linux

Target Machines

• Metasploitable2
• Windows 7 (Unpatched)
• Ubuntu Server (Optional)

Network Type

• Host Only Network
or
• Internal Network

--------------------------------------------------------------------------------

# 9. Overall Architecture

                User
                  │
                  ▼
          React Dashboard
                  │
                  ▼
           FastAPI Backend
                  │
       Assessment Engine
                  │
 ┌─────────────────────────────────┐
 │ Host Discovery                  │
 │ Port Scanner                    │
 │ Service Enumeration             │
 │ Vulnerability Scanner           │
 │ CVE Intelligence                │
 │ Exploitation Engine             │
 │ Packet Analysis                 │
 │ Report Generator                │
 └─────────────────────────────────┘
                  │
            PostgreSQL
                  │
        Internal Virtual Lab

--------------------------------------------------------------------------------

# 10. Development Methodology

The project follows a professional VAPT lifecycle.

Planning

↓

Lab Setup

↓

Network Discovery

↓

Host Enumeration

↓

Port Scanning

↓

Service Detection

↓

Vulnerability Assessment

↓

CVE Analysis

↓

Exploit Mapping

↓

Controlled Exploitation

↓

Privilege Escalation

↓

Lateral Movement

↓

Packet Analysis

↓

Report Generation

↓

Project Documentation

--------------------------------------------------------------------------------

# 11. Development Phases

Phase 0
Project Planning

Phase 1
Lab Setup

Phase 2
Backend Development

Phase 3
Frontend Development

Phase 4
Dashboard Development

Phase 5
Host Discovery

Phase 6
Port Scanner

Phase 7
Service Enumeration

Phase 8
Vulnerability Assessment

Phase 9
CVE Intelligence

Phase 10
Metasploit Integration

Phase 11
Controlled Exploitation

Phase 12
Privilege Escalation

Phase 13
Lateral Movement

Phase 14
Packet Analysis

Phase 15
Professional Reporting

Phase 16
Testing

Phase 17
Documentation

Phase 18
Deployment

--------------------------------------------------------------------------------

# 12. Project Modules

Core Modules

• Authentication (Optional)
• Dashboard
• Host Discovery
• Port Scanner
• Service Enumeration
• Vulnerability Scanner
• CVE Intelligence
• Metasploit Integration
• Exploitation Module
• Privilege Escalation
• Lateral Movement
• Packet Analysis
• Reporting Engine
• Settings
• Logs

--------------------------------------------------------------------------------

# 13. Frontend Pages

Dashboard

Hosts

Network Topology

Port Scan Results

Vulnerabilities

Exploitation

Packet Analysis

Reports

Settings

About

--------------------------------------------------------------------------------

# 14. Backend Services

Host Discovery Service

Port Scanner Service

Service Detection Service

Vulnerability Assessment Service

CVE Mapping Service

Metasploit Service

Packet Analysis Service

Report Generator

Logging Service

--------------------------------------------------------------------------------

# 15. Database Tables

Users

Hosts

Services

Ports

Operating Systems

Vulnerabilities

CVEs

Exploits

Reports

Logs

Settings

--------------------------------------------------------------------------------

# 16. Expected Outputs

Host Inventory

Open Ports

Running Services

Detected Operating Systems

Known Vulnerabilities

CVE Mapping

Exploit Mapping

Packet Captures

Risk Matrix

Executive Summary

Technical Report

HTML Report

PDF Report

--------------------------------------------------------------------------------

# 17. Learning Outcomes

After completing this project, the following skills will be demonstrated:

• Internal Network Penetration Testing
• Network Enumeration
• Service Identification
• Vulnerability Assessment
• Exploitation Workflow
• CVE Analysis
• Packet Inspection
• Security Automation
• Python Development
• FastAPI Development
• React Development
• Dashboard Design
• Report Generation
• GitHub Project Management

--------------------------------------------------------------------------------

# 18. Repository Structure

Network-VAPT-Lab/

backend/

frontend/

database/

automation/

scans/

reports/

docs/

screenshots/

wireshark/

docker/

README.md

requirements.txt

--------------------------------------------------------------------------------

# 19. Final Deliverables

✔ Full Stack Web Application

✔ React Dashboard

✔ FastAPI Backend

✔ PostgreSQL Database

✔ Automated Host Discovery

✔ Port Scanning Engine

✔ Service Enumeration

✔ Vulnerability Assessment

✔ CVE Intelligence

✔ Metasploit Integration

✔ Controlled Exploitation

✔ Privilege Escalation Demonstration

✔ Lateral Movement Demonstration

✔ Packet Analysis

✔ HTML Report

✔ PDF Report

✔ Complete Documentation

✔ GitHub Repository

✔ Resume-ready Enterprise Project

--------------------------------------------------------------------------------

# 20. Future Enhancements

• Active Directory Lab Integration
• LDAP Enumeration
• Kerberos Assessment
• BloodHound Integration
• CVSS v4 Support
• Threat Intelligence Feeds
• Asset Management
• Scheduled Scans
• Multi-user Authentication
• RBAC
• Docker Deployment
• Cloud Lab Support
• AI-assisted Vulnerability Prioritization

--------------------------------------------------------------------------------

END OF PROJECT BLUEPRINT