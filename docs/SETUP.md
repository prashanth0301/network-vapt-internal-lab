# Setup Guide

## Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Nmap
- VirtualBox or VMware Workstation
- Nessus or OpenVAS (optional, for vulnerability scanning)
- Metasploit Framework
- Wireshark (with tshark CLI)

---

## 1. Clone the Repository

```bash
git clone https://github.com/yourusername/Network-VAPT-Lab.git
cd Network-VAPT-Lab
```

---

## 2. Virtual Lab Setup

### 2.1 Install Hypervisor
- Install [VirtualBox](https://www.virtualbox.org/) or VMware Workstation

### 2.2 Configure Host-Only Network
- Create a Host-Only adapter in VirtualBox: `192.168.56.0/24`

### 2.3 Import VMs
| VM | Download | Notes |
|----|----------|-------|
| Kali Linux | [kalilinux.org](https://www.kali.org/get-kali/) | Attacker machine |
| Metasploitable 2 | [sourceforge.net](https://sourceforge.net/projects/metasploitable/) | Vulnerable Linux |
| Windows 7 (unpatched) | Microsoft evaluation center | Vulnerable Windows |

### 2.4 Network Configuration
| VM | IP Address | Adapter |
|----|-----------|---------|
| Kali Linux | 192.168.56.2 | Host-Only |
| Metasploitable 2 | 192.168.56.3 | Host-Only |
| Windows 7 | 192.168.56.4 | Host-Only |

---

## 3. Backend Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or .\venv\Scripts\Activate.ps1  # Windows

# Install dependencies
pip install -r backend/requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your database credentials

# Run database migrations
cd backend
alembic upgrade head

# Start the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Environment Variables

```
DATABASE_URL=postgresql://user:password@localhost:5432/vapt_lab
SECRET_KEY=your-secret-key-here
LOG_LEVEL=INFO
CORS_ORIGINS=http://localhost:5173
```

---

## 4. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The frontend runs at `http://localhost:5173`.

---

## 5. Docker Setup (Alternative)

```bash
docker-compose -f docker/docker-compose.yml up -d
```

---

## 6. Verify Installation

1. Backend health check: `curl http://localhost:8000/api/v1/health`
2. Frontend: open `http://localhost:5173`
3. API docs: `http://localhost:8000/docs`
4. Test host discovery against your lab network
