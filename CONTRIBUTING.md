# Contributing to Network VAPT Platform

Thank you for your interest in contributing to the **Network VAPT Platform**! Whether you are fixing a bug, adding a feature, improving documentation, or reporting an issue, your help makes this project better for every security team that uses it.

Please take a moment to read this guide before opening an issue or pull request.

---

## Development Environment

The following software is required to build and run the project locally:

| Software | Version | Purpose |
|---|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | 24.0+ | Container runtime (backend, frontend, PostgreSQL, lab targets) |
| Docker Compose | v2.20+ | Orchestrates the full stack from `docker/docker-compose.yml` |
| [Python](https://www.python.org/) | 3.11+ | Backend runtime (FastAPI) |
| [Node.js](https://nodejs.org/) | 20+ | Frontend tooling (Vite, React, Vitest) |
| [PostgreSQL](https://www.postgresql.org/) | 16 | Primary database (runs inside Docker for development) |
| [Git](https://git-scm.com/) | 2.30+ | Version control |

Optional but recommended for full feature coverage:

- **Wireshark / Npcap** — live packet capture backend (Scapy is used automatically when no capture tool is installed)
- **Nmap / OpenVAS / Metasploit** — scanner and exploit-verification integrations
- **Ruff** — Python linter (`pip install ruff`)

---

## Setup

### 1. Fork and clone

```bash
git clone <your-fork-url>
cd Network-VAPT-Internal-Lab
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Set at minimum `POSTGRES_PASSWORD` and `JWT_SECRET` (never commit `.env`).

### 3. Run the full stack with Docker (recommended)

```bash
cd docker
docker compose --env-file ..\.env up -d --build
```

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |

On first startup the backend creates the database schema and bootstraps a default administrator (`admin` / `Admin@123`). **Change this password immediately in any shared environment.**

### 4. Local development (optional)

Backend:

```bash
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1        # Windows
# source .venv/bin/activate      # Linux / macOS
pip install -r requirements.txt
pip install -r requirements-dev.txt    # pytest and dev tooling
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Frontend (separate terminal):

```bash
cd frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` requests to `http://localhost:8000`.

---

## Branch Strategy

The project follows a simple, stable branching model:

| Branch | Purpose |
|---|---|
| `main` | Production-ready code. Always deployable, reviewed, and passing tests. |
| `feature/*` | New functionality, e.g. `feature/report-scheduling`. Branched from and merged back into `main`. |
| `bugfix/*` | Defect fixes for non-urgent issues, e.g. `bugfix/dashboard-trend-timezone`. |
| `hotfix/*` | Urgent fixes for issues in the current release, e.g. `hotfix/bootstrap-secret-log`. |

**Rules:**

- Never commit directly to `main`.
- Branch names must be lowercase and use `kebab-case` after the prefix.
- Keep a branch focused on a single concern; avoid unrelated changes in the same branch.
- Delete your branch after it has been merged.

---

## Coding Standards

### Backend (Python / FastAPI)

- **FastAPI** for API routes — routers under `backend/app/api/v1/`.
- **SQLAlchemy 2.0 (async)** with `asyncpg` — use `AsyncSession`, `select()`, and async queries only. No synchronous DB access.
- **Async-first code** — avoid blocking calls in request handlers; run subprocess/IO work with `asyncio.to_thread` where necessary.
- **Type hints** on all function signatures, endpoint parameters, and return values.
- **Pydantic v2 models** for all request/response validation (`backend/app/schemas/`); keep business logic in the service layer (`backend/app/services/`), not in routers.
- UUID primary keys; no sequential IDs.
- Follow existing module structure and naming conventions (`*_service.py`, `*_api.py`).

### Frontend (React / TypeScript)

- **React 18 + TypeScript** with Vite.
- **Component-based architecture** — shared UI lives in `frontend/src/components/`, feature pages in `frontend/src/pages/`, API clients in `frontend/src/services/`, shared types in `frontend/src/types/`.
- Strict TypeScript — run `npm run build` (runs `tsc -b`) before pushing; fix all type errors.
- **ESLint formatting** — run `npm run lint` and ensure zero warnings.

### General

- Keep changes small and reviewable; a pull request should do one thing.
- Do not add comments unless they explain non-obvious logic.
- No new secrets, hardcoded credentials, or environment-specific absolute paths.

---

## Commit Message Style

Use the **Conventional Commits** format: a type prefix, followed by a short imperative description.

| Type | When to use |
|---|---|
| `feat:` | New feature or capability |
| `fix:` | Bug fix |
| `docs:` | Documentation-only changes |
| `refactor:` | Code change that neither fixes a bug nor adds a feature |
| `test:` | Adding or updating tests |
| `perf:` | Performance improvement |

**Examples:**

```
feat: add scheduled assessment reruns
fix: resolve interface list rendering on packet analysis page
docs: document report persistence in release notes
refactor: extract host discovery into dedicated service
test: cover 401 handling for capture endpoints
perf: index vulnerabilities by assessment id
```

Rules:

- The subject line is imperative, lowercase, and under ~72 characters.
- Reference the issue when applicable: `fix: correct login redirect (#123)`.
- One logical change per commit; separate commits for unrelated changes.

---

## Before Opening a Pull Request

Please ensure that:

- [ ] **Backend tests pass successfully** — run the full pytest suite before opening the PR.
- [ ] **Frontend builds without errors** — `npm run build` (TypeScript + Vite) completes cleanly.
- [ ] **New functionality includes appropriate tests** where applicable — cover new endpoints, services, or components with unit/integration tests.
- [ ] **Documentation is updated if behavior changes** — `README.md`, `docs/`, and `RELEASE_NOTES.md` where relevant.
- [ ] **No secrets, credentials, or generated artifacts are committed** — no `.env`, tokens, passwords, build output, logs, or stray files.
- [ ] **Docker deployment continues to work** — verify the full stack still starts with `docker compose --env-file ..\.env up -d --build`.

Additionally, for a smooth review:

- [ ] Screenshots included for UI changes (before/after where applicable)
- [ ] Branch rebased on latest `main`
- [ ] Commits follow the Conventional Commits format

## Pull Requests

All changes land on `main` via pull request.

**Process**

1. Push your branch and open a PR with a clear title and description.
2. Describe the change, why it is needed, and how it was verified.
3. Link any related issues (`Closes #123`).
4. Keep the PR focused; split large changes into multiple PRs.
5. A maintainer will review. Address review feedback in follow-up commits.

---

## Testing

**Backend (pytest):**

```bash
cd backend
pip install -r requirements-dev.txt
pytest tests/ -v --asyncio-mode=auto
```

The suite (647 tests) requires the PostgreSQL test database (`vapt_test`) — run it with the `vapt-db` container up. Run the subset relevant to your change while developing, but the full suite must pass before merge.

**Frontend (Vitest):**

```bash
cd frontend
npm test          # vitest run
npm run lint      # eslint, zero warnings
npm run build     # tsc -b + vite build
```

If your change touches new behavior, add tests alongside the code.

---

## Reporting Bugs

Before reporting, please:

1. Search existing issues and the `docs/TROUBLESHOOTING.md` guide to avoid duplicates.
2. Reproduce the issue on the latest `main` when possible.
3. Open an issue titled `[Bug] <short summary>` and include:

   - **Environment** — OS, Docker/Python/Node versions, deployment mode (Docker Compose vs. local dev)
   - **Steps to reproduce** — numbered, minimal steps
   - **Expected behavior** — what should happen
   - **Actual behavior** — what actually happens, including error messages
   - **Logs** — relevant excerpts from `backend/logs/vapt.log`
   - **Screenshots** — where visual output is involved
   - **Impact** — severity and any workaround you found

Use the `bug` label and provide as much detail as possible; incomplete reports slow down fixes.

---

## Feature Requests

New features should be proposed before implementation:

1. Open an issue titled `[Feature] <short summary>` using the `enhancement` label.
2. Describe the **problem** it solves and the **proposed behavior**, including example UI/API sketches where helpful.
3. Note affected areas (backend router/service, frontend page, database model, docs) and any migration impact.
4. Discuss scope with maintainers before writing code — large features may need a design proposal first.

Once a feature is agreed upon, implement it on a `feature/*` branch following the standards and PR process above.

---

## Code of Conduct

Be respectful and constructive in all discussions, issues, and reviews. Focus feedback on the code, not the person.

---

## Questions?

- **Documentation:** `docs/INSTALLATION.md`, `docs/USER_GUIDE.md`, `docs/API_DOCUMENTATION.md`, `docs/ARCHITECTURE.md`
- **Setup problems:** `docs/TROUBLESHOOTING.md`
- **Issues:** Use the GitHub issue tracker; assign the `question` label for help.

Thank you again for contributing to the Network VAPT Platform!
