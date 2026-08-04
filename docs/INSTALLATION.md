# Installation Guide

## System Requirements

### Minimum Hardware

| Component | Requirement |
|---|---|
| CPU | 4 cores |
| RAM | 8 GB |
| Disk | 20 GB free |
| Network | Adapter with access to target networks |

### Software Prerequisites

| Software | Version | Purpose |
|---|---|---|
| Docker | 24.0+ | Container runtime |
| Docker Compose | v2.20+ | Multi-container orchestration |
| Python | 3.11+ | Backend (for local development) |
| Node.js | 20+ | Frontend (for local development) |
| Nmap | 7.80+ | Port scanning (installed on host or via Docker) |
| Git | 2.30+ | Source control |

---

## Docker Deployment (Recommended)

### Step 1: Clone and Configure

```bash
git clone <repository-url>
cd Network-VAPT-Internal-Lab

# Create your environment file
cp .env.example .env
```

### Step 2: Edit `.env`

```ini
# Required — change these for production
POSTGRES_PASSWORD=your_secure_password
JWT_SECRET=your_jwt_secret_key

# Optional overrides
POSTGRES_USER=vapt
POSTGRES_DB=vapt_db
CORS_ORIGINS=["http://localhost:5173"]
```

### Step 3: Start Services

```bash
cd docker
docker compose --env-file ..\.env up -d --build
```

This starts 5 containers:

| Container | Port | Purpose |
|---|---|---|
| `vapt-db` | 5432 | PostgreSQL 16 database |
| `vapt-backend` | 8000 | FastAPI backend |
| `vapt-frontend` | 5173 | React SPA (served by `serve`) |
| `vapt-vulnapache` | — | Vulnerable target for lab testing |
| `vapt-ftp` | — | FTP service for lab testing |

### Step 4: Verify

```bash
# Check all containers are running
docker ps --filter "name=vapt"

# Check backend health
curl http://localhost:8000/api/v1/health

# Open the UI
open http://localhost:5173
```

### Step 5: Default Login

Navigate to `http://localhost:5173` and log in:

- **Username:** `admin`
- **Password:** `Admin@123`

> **Important:** Change the admin password immediately in production environments.

---

## Local Development Setup

### Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp ../.env.example .env

# Start the backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start dev server (with proxy to backend)
npm run dev
```

The Vite dev server runs on `http://localhost:5173` and proxies `/api` requests to `http://localhost:8000`.

### Database

The backend automatically:
1. Creates all tables on first startup (via SQLAlchemy `Base.metadata.create_all`)
2. Creates the default admin user when the `users` table is empty
3. Seeds default application settings

No manual migration step is required for development. For production, Alembic is configured:

```bash
cd backend
alembic upgrade head
```

---

## Environment Variables

| Variable | Default | Required | Description |
|---|---|---|---|
| `POSTGRES_USER` | `vapt` | No | PostgreSQL username |
| `POSTGRES_PASSWORD` | `vaptpassword` | **Yes** | PostgreSQL password |
| `POSTGRES_HOST` | `localhost` | No | PostgreSQL host |
| `POSTGRES_PORT` | `5432` | No | PostgreSQL port |
| `POSTGRES_DB` | `vapt_db` | No | Database name |
| `JWT_SECRET` | *(default)* | **Yes** | Secret key for JWT signing |
| `JWT_EXPIRATION_MINUTES` | `30` | No | Access token lifetime |
| `JWT_REFRESH_EXPIRATION_DAYS` | `7` | No | Refresh token lifetime |
| `ADMIN_USERNAME` | `admin` | No | Default admin username |
| `ADMIN_EMAIL` | `admin@networkvapt.local` | No | Default admin email |
| `ADMIN_PASSWORD` | `Admin@123` | No | Default admin password |
| `AUTO_CREATE_ADMIN` | `true` | No | Auto-create admin on empty DB |
| `CORS_ORIGINS` | `["http://localhost:5173"]` | No | Allowed CORS origins |
| `LOG_LEVEL` | `INFO` | No | Logging level |
| `LOG_FORMAT` | `json` | No | Log output format (`json` or `text`) |
| `NVD_API_KEY` | *(none)* | No | NVD API key for CVE enrichment |
| `MSF_RPC_HOST` | `127.0.0.1` | No | Metasploit RPC host |
| `MSF_RPC_PORT` | `55553` | No | Metasploit RPC port |

---

## Network Configuration

### Target Network

For internal lab testing, the platform expects targets on accessible subnets. The default lab setup includes:

- `vapt-vulnapache` — Apache with known vulnerabilities
- `vapt-ftp` — FTP service with default credentials

### Firewall Rules

Ensure the following ports are accessible:

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 5173 | TCP | Inbound | Frontend UI |
| 8000 | TCP | Inbound | Backend API |
| 5432 | TCP | Internal | Database (Docker network only) |

---

## Troubleshooting

### Backend won't start

```bash
# Check logs
docker logs vapt-backend

# Common issue: database not ready
docker compose --env-file ..\.env up -d db
# Wait for healthcheck to pass, then:
docker compose --env-file ..\.env up -d backend
```

### Frontend shows "Failed to load"

```bash
# Verify backend is healthy
curl http://localhost:8000/api/v1/health

# Check CORS settings in .env
CORS_ORIGINS=["http://localhost:5173"]
```

### Database connection refused

```bash
# Verify PostgreSQL is running
docker ps --filter "name=vapt-db"

# Check database health
docker exec vapt-db pg_isready -U vapt -d vapt_db
```

### Nmap not found (scanning)

Nmap must be available inside the backend container. The Dockerfile installs it automatically. For local development, install Nmap on your system and ensure it's in the PATH.

---

## Updating

```bash
# Pull latest changes
git pull

# Rebuild and restart
cd docker
docker compose --env-file ..\.env up -d --build

# Database migrations (if any)
docker exec vapt-backend alembic upgrade head
```

---

## Uninstalling

```bash
cd docker
docker compose --env-file ..\.env down -v  # -v removes volumes (database data)
```
