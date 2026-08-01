# START_BACKEND.md — Backend Startup Guide (Windows)

## Start the backend (single command)

From the repository root:

```powershell
.\start_backend.ps1
```

That is all. The script automatically:

1. Checks whether port `8000` is already in use.
2. If the owner is a **stale Python/Uvicorn process of this project**, it terminates it safely.
3. Waits until the port is released.
4. Starts the backend (`uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`).
5. Waits for `http://localhost:8000/docs` to return **HTTP 200** and reports success.

Expected output:

```
==> Network VAPT backend startup (port 8000, bind 0.0.0.0, reload=True)
WARN Port 8000 is owned by a stale backend (PID 9772) - killing it safely.
==> Terminating stale backend PID(s): 9772
OK  Port 8000 released.
OK  Started backend process PID 14588.
==> Waiting for http://localhost:8000/docs to return 200 (up to 45s)...
OK  Backend is healthy - PID 14588 listening on port 8000
OK  API docs:  http://localhost:8000/docs
OK  Health:    http://localhost:8000/api/v1/health
```

## Stop the backend

```powershell
.\start_backend.ps1 -Stop
```

This finds all Python processes belonging to this project (matched by
command line: `app.main:app` or this repo's `backend` folder) and terminates
them, then waits for port 8000 to be released.

You can also stop it from the backend's own console window with `Ctrl+C`.

## Options

| Option | Default | Description |
|---|---|---|
| `-Port <n>` | `8000` | Port to bind. |
| `-HostAddr <ip>` | `0.0.0.0` | Bind address (`127.0.0.1` = localhost only). |
| `-Reload:$false` | `$true` | Disable uvicorn `--reload` (fewer processes). |
| `-Stop` | off | Stop the running backend instead of starting it. |
| `-Foreground` | off | Run uvicorn in the current console (blocks; useful to see tracebacks live). |
| `-Python <path>` | auto | Explicit interpreter path (e.g. `-Python "C:\...\python.exe"`). |
| `-WaitSeconds <n>` | `45` | Health-check timeout. |

## Why WinError 10013 happens

`WinError 10013` (WSAEACCES) on port 8000 almost always means **the port is
already bound by a previous backend instance**. The investigation found a
four-process architecture that makes stale instances extremely hard to kill
manually:

```
py.exe                      <- launcher  (matches "app.main:app")
└── python.exe reloader     <- uvicorn --reload parent (matches "app.main:app")
    └── python.exe worker   <- "python -c \"from multiprocessing.spawn import
                                spawn_main; spawn_main(parent_pid=<reloader>)\""
                                -- does NOT contain "app.main:app" at all!
```

- **The worker inherits the listening socket.** When the reloader dies, the
  worker keeps serving and keeps the port bound.
- **`netstat` attributes the port to a PID that no longer exists.** The
  inherited socket is reported against the process that created it, so
  `netstat`/`tasklist` show a dead PID and `taskkill /PID <that>` fails with
  "not found". This is the trap that forces the daily manual hunt.
- **Windows does not kill child processes when the console closes.** Closing
  VS Code / PowerShell only detaches; verified on this machine: the port
  owner's parent had already exited (orphaned process).
- **`SO_REUSEADDR` allows a second instance to bind the same port anyway.**
  uvicorn enables reuse on Windows, so a second `py -m uvicorn ... --reload`
  can bind on top of the first (reported against a different address/owner),
  and incoming connections are then routed unpredictably between instances.
  The diagnostics in `start_backend.ps1` therefore list *all* owning PIDs.
- **The reloader exits when its worker dies.** Killing the worker (child
  first) makes the reloader terminate itself; killing the reloader alone
  leaves the worker holding the port. The script kills workers before
  reloaders on purpose.
- Secondary cause (checked automatically by the script): Windows **excluded
  port ranges** (`netsh interface ipv4 show excludedportrange protocol=tcp`).
  A port inside an excluded range fails to bind even when nothing is
  listening. Port 8000 is not affected on this machine.

## Safety — what the script will NOT kill

Only processes that are `python.exe`/`py.exe` **and** whose command line
contains `app.main:app` or this repository's `backend` folder are terminated.
If port 8000 is owned by any other application, the script **refuses to
start** and tells you which PID/process owns the port.

## Troubleshooting

### Port still occupied after `-Stop`

```powershell
netstat -ano | findstr :8000
tasklist /FI "PID eq <pid>"
taskkill /PID <pid> /T /F   # only if it is the python backend from this project
```

### "Port is in use by PID <n>: <other app>"

Another application owns port 8000 (e.g. another server). Close that
application, or start on another port:

```powershell
.\start_backend.ps1 -Port 8001
```

### Backend starts but health check fails

The script prints diagnostics covering:

- **Port state** — who owns the port, or "free but nothing listening"
  (uvicorn crashed early).
- **Excluded port range** — whether port 8000 falls inside a Windows
  excluded range.
- **Firewall** — only relevant when accessing the backend from another
  machine (binding `0.0.0.0`). Localhost is never affected by the firewall.
- **Startup exception** — run in the foreground to see the traceback:

```powershell
.\start_backend.ps1 -Foreground
```

Typical causes: missing `.env` / environment variables, a DB connection
failure (`postgres` not running), or an import error after code changes.

### Execution policy error (`running scripts is disabled`)

The project uses `RemoteSigned` for the current user. If you see a policy
error, run once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

or bypass for a single run:

```powershell
powershell -ExecutionPolicy Bypass -File .\start_backend.ps1
```

### Firewall prompts

The first start with `--host 0.0.0.0` may show a Windows Firewall prompt for
`python.exe`. Allow it on Private networks if lab VMs need to reach the API;
`localhost` works regardless.

## Limitations

- The script kills all Python processes matching this project's signature;
  if you run multiple copies of this repo, all of them are stopped by
  `-Stop`. (The repository is intended to run as a single backend.)
- No auto-restart on crash — run the script again after fixing the cause.
- The backend runs in its own console window; closing that window stops the
  backend. Closing the *launcher* terminal does not stop it (intentional —
  the backend keeps running; use `.\start_backend.ps1 -Stop`).
- `-Reload:$false` is recommended when running the backend unattended for
  long periods (fewer processes, no file-watcher overhead).
- The first HTTP request after a cold start can take several seconds (lazy
  imports, DB pool init). The health check waits up to 20 s per request; on a
  very slow machine increase the overall budget with `-WaitSeconds 90`.
