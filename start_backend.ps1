<#
====================================================================================
  start_backend.ps1 - Network VAPT Platform backend startup script (Windows)

  Purpose:
    Always start the backend with a single command, without manual taskkill,
    netstat or troubleshooting:

        .\start_backend.ps1

  Flow:
    Check port 8000 -> safely kill stale backend -> wait until port released
    -> start uvicorn -> verify http://localhost:8000/docs returns 200.

  Safety:
    Only processes that are python.exe (or py.exe) AND belong to THIS project
    (command line matches "app.main:app" or this repository's backend folder)
    are terminated. Unrelated applications are never killed.

  Options:
    .\start_backend.ps1 -Stop              Stop the running backend.
    .\start_backend.ps1 -Port 9000         Use a different port.
    .\start_backend.ps1 -HostAddr 127.0.0.1  Bind to localhost only.
    .\start_backend.ps1 -Reload:$false     Start without --reload.
    .\start_backend.ps1 -WaitSeconds 60    Longer startup timeout.
    .\start_backend.ps1 -Foreground        Run in the current console (blocking).
    .\start_backend.ps1 -Python "C:\path\to\python.exe"  Override interpreter.
====================================================================================
#>

[CmdletBinding()]
param(
    [int]    $Port        = 8000,
    [string] $HostAddr    = '0.0.0.0',
    [bool]   $Reload      = $true,
    [switch] $Stop,
    [switch] $Foreground,
    [string] $Python      = '',
    [int]    $WaitSeconds = 45
)

$ErrorActionPreference = 'Stop'

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir  = Join-Path $ProjectRoot 'backend'
$AppString   = 'app.main:app'
$HealthUrl   = "http://localhost:$Port/docs"

function Write-Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "OK  $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "WARN $msg" -ForegroundColor Yellow }
function Write-Err([string]$msg)  { Write-Host "ERR  $msg" -ForegroundColor Red }

function Get-ProcName($Proc) { if ($Proc) { return $Proc.Name } return 'unknown' }

# ----------------------------------------------------------------------------
# Project process detection (safe)
#
# A backend started via "py -m uvicorn app.main:app --reload" on Windows
# actually consists of up to 4 processes:
#   1. py.exe / pyw.exe launcher
#   2. python.exe reloader  ("-m uvicorn app.main:app ...")
#   3. python.exe worker    (uvicorn reload worker: command line is
#      "python -c \"from multiprocessing.spawn import spawn_main;
#       spawn_main(parent_pid=<reloader>, ...)\"" -- it does NOT mention
#       uvicorn or app.main:app at all)
# The worker inherits the listening socket, so the port survives even when
# the reloader is killed. We follow parent_pid links from any process that
# proves to belong to this project (or from a port-owner seed) to find it.
# ----------------------------------------------------------------------------
function Get-ProjectProcesses([int[]]$SeedPids = @()) {
    $known = @{}
    foreach ($s in $SeedPids) { $known[[int]$s] = $true }
    $result = @()
    $anyAdded = $true
    while ($anyAdded) {
        $anyAdded = $false
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
            $pidNow = [int]$_.ProcessId
            if ($known.ContainsKey($pidNow)) { return }
            $isOurs = $false
            if (($_.Name -match '^python') -or ($_.Name -in @('py.exe', 'pyw.exe'))) {
                if ($_.CommandLine -match [regex]::Escape($AppString) -or
                    $_.CommandLine -match [regex]::Escape($BackendDir)) {
                    $isOurs = $true
                }
                elseif ($_.CommandLine -match 'spawn_main\(parent_pid=(\d+)') {
                    if ($known.ContainsKey([int]$matches[1])) { $isOurs = $true }
                }
            }
            if ($isOurs) {
                $known[$pidNow] = $true
                $result += $_
                $anyAdded = $true
            }
        }
    }
    return $result
}

function Test-ProjectProcess([int]$ProcessId) {
    if (-not $ProcessId) { return $false }
    $p = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
    if (-not $p) { return $false }
    return (($p.Name -match '^python') -or ($p.Name -in @('py.exe', 'pyw.exe'))) -and
           ($p.CommandLine -match [regex]::Escape($AppString) -or
            $p.CommandLine -match [regex]::Escape($BackendDir))
}

function Get-PortOwnerPid([int]$PortNumber) {
    $conns = Get-NetTCPConnection -LocalPort $PortNumber -State Listen -ErrorAction SilentlyContinue
    if (-not $conns) { return @() }
    # Multiple PIDs can own the same port on Windows (uvicorn --reload sockets
    # are inherited by the worker; SO_REUSEADDR lets a second instance bind).
    $unique = @($conns | Select-Object -ExpandProperty OwningProcess -Unique)
    return $unique
}

function Get-PortOwnerPidFirst([int]$PortNumber) {
    $owners = Get-PortOwnerPid $PortNumber
    if (-not $owners) { return $null }
    return $owners[0]
}

function Test-PortFree([int]$PortNumber) {
    return -not (Get-NetTCPConnection -LocalPort $PortNumber -State Listen -ErrorAction SilentlyContinue)
}

function Wait-PortFree([int]$PortNumber, [int]$MaxSeconds) {
    $deadline = (Get-Date).AddSeconds($MaxSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-PortFree $PortNumber) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Get-PythonExe {
    if ($Python) { return $Python }
    if (Get-Command py -ErrorAction SilentlyContinue) { return 'py' }
    if (Get-Command python -ErrorAction SilentlyContinue) { return 'python' }
    throw 'No Python interpreter found. Install Python (py launcher preferred) or pass -Python "<path>"'
}

# ----------------------------------------------------------------------------
# Stop the backend (also used by -Stop)
# ----------------------------------------------------------------------------
function Stop-Backend([int]$PortNumber, [bool]$Silent = $false) {
    # Seed with port owners so orphaned uvicorn reload workers (whose parents
    # are already dead) are found via their spawn_main(parent_pid=...) line.
    $seedOwners = @(Get-PortOwnerPid $PortNumber)
    if (-not $Silent) { Write-Step "Stopping backend (port $PortNumber)..." }
    $stopped = @()
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        $targets = @(Get-ProjectProcesses $seedOwners)
        if (-not $targets) { break }
        if (-not $Silent) {
            Write-Step "Terminating backend PID(s): $($targets.ProcessId -join ', ')"
        }
        foreach ($t in $targets) { $stopped += $t.ProcessId }
        # Kill workers (spawn children) before reloaders so the reloader does
        # not respawn them. Stop-Process is synchronous enough for our loop.
        $parents = @($targets | Where-Object { $_.CommandLine -match 'app\.main:app' })
        $children = @($targets | Where-Object { $parents.ProcessId -notcontains $_.ProcessId })
        foreach ($c in $children) { Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue }
        foreach ($p in $parents)  { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 800
        if (Wait-PortFree $PortNumber 5) { break }
    }
    if ($stopped -and -not $Silent) {
        Write-Ok "Stopped backend PID(s): $($stopped -join ', ')"
    }
    elseif (-not $stopped -and -not $Silent) {
        Write-Warn 'No running backend process found for this project.'
    }
    if (-not (Wait-PortFree $PortNumber 15)) {
        foreach ($o in @(Get-PortOwnerPid $PortNumber)) {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $o" -ErrorAction SilentlyContinue
            Write-Err "Port $PortNumber still in use by PID $o ($(Get-ProcName $proc))."
        }
        return $false
    }
    return $true
}

# ----------------------------------------------------------------------------
# Diagnostics when the backend fails to become healthy
# ----------------------------------------------------------------------------
function Show-FailureDiagnostics([int]$PortNumber) {
    Write-Host ''
    Write-Err "Backend did not become healthy at $HealthUrl within $WaitSeconds seconds."
    Write-Step 'Diagnostics:'

    # 1. Port state
    $owners = Get-PortOwnerPid $PortNumber
    if ($owners) {
        foreach ($o in $owners) {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId = $o" -ErrorAction SilentlyContinue
            Write-Warn "Port $PortNumber is currently owned by PID $o ($(Get-ProcName $proc))."
            if ($proc) { Write-Warn "  Command: $($proc.CommandLine)" }
            Write-Warn '  If this is NOT a python backend process, it is probably another application.'
            Write-Warn '  Do not force-kill it - find and close the owning application instead.'
        }
    }
    else {
        Write-Warn 'Port is free but nothing is listening: the new uvicorn process exited early.'
        Write-Warn '  This usually means a startup exception (import error, missing env, bad config).'
    }

    # 2. Windows excluded port range (another real cause of WinError 10013)
    $excluded = netsh interface ipv4 show excludedportrange protocol=tcp 2>$null
    $rangeHit = $false
    foreach ($line in $excluded) {
        if ($line -match '^\s*(\d+)\s+(\d+)\s*$') {
            $start = [int]$matches[1]; $end = [int]$matches[2]
            if ($PortNumber -ge $start -and $PortNumber -le $end) {
                $rangeHit = $true
                Write-Err "Port $PortNumber falls inside a Windows EXCLUDED PORT RANGE ($start-$end)."
                Write-Err '  Binds to this port will fail with WinError 10013 even when nothing is listening.'
                Write-Err '  Fix: run this as Administrator and remove the range, or use another port:'
                Write-Err "    netsh interface ipv4 delete excludedportrange protocol=tcp startport=$start numberofports=$($end - $start + 1)"
            }
        }
    }
    if (-not $rangeHit) {
        Write-Ok "Port $PortNumber is not inside any Windows excluded port range."
    }

    # 3. Firewall (only relevant when reaching the backend from another machine)
    try {
        $fw = netsh advfirewall show allprofiles state 2>$null | Select-String 'State'
        Write-Warn "Firewall profiles: $($fw -join ' | ')"
        if ($HostAddr -eq '0.0.0.0') {
            Write-Warn '  Binding to 0.0.0.0 exposes the API to the network - make sure the lab firewall'
            Write-Warn '  permits inbound TCP 8000 for the machines that need to reach it.'
        }
        else {
            Write-Ok "Binding to $HostAddr (localhost only) - firewall does not apply."
        }
    }
    catch { Write-Warn 'Could not query firewall state (requires admin).' }

    # 4. Startup exception
    Write-Step 'To see the actual startup exception:'
    Write-Host "   Set-Location '$BackendDir'"
    Write-Host "   py -m uvicorn $AppString --reload --host $HostAddr --port $PortNumber"
    Write-Host '   (or run this script with -Foreground to keep the traceback visible)'
    Write-Host ''
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
try {
    if (-not (Test-Path $BackendDir)) {
        throw "Backend directory not found: $BackendDir`n  Run this script from the repository root or pass -BackendDir."
    }

    if ($Stop) {
        Write-Step 'Stop mode requested.'
        if (Stop-Backend $Port) { Write-Ok "Backend stopped, port $Port released." }
        else { Write-Err "Could not stop backend (see diagnostics above)."; exit 1 }
        exit 0
    }

    Write-Step "Network VAPT backend startup (port $Port, bind $HostAddr, reload=$Reload)"

    # --- 1. Detect port 8000 usage ---
    $owners = @(Get-PortOwnerPid $Port)
    $foreign = @()
    foreach ($o in $owners) {
        $alive = Get-Process -Id $o -ErrorAction SilentlyContinue
        if ($alive -and -not (Test-ProjectProcess $o)) {
            $foreign += @{ Pid = $o; Name = (Get-ProcName $alive) }
        }
    }
    if ($foreign.Count -gt 0) {
        foreach ($f in $foreign) {
            Write-Err "Port $Port is in use by PID $($f.Pid): $($f.Name)."
        }
        Write-Err 'Refusing to terminate unrelated processes.'
        Write-Err "Close the owning application or start with a different port: .\start_backend.ps1 -Port $($Port + 1)"
        exit 1
    }
    elseif ($owners.Count -gt 0) {
        Write-Warn "Port $Port is owned by stale backend PID(s): $($owners -join ', ') - killing them safely."
    }
    else {
        Write-Ok "Port $Port is free."
    }

    # --- 2. Kill stale backend (reloader, py launcher and orphaned workers) ---
    $stale = @(Get-ProjectProcesses $owners)
    if ($stale) {
        Write-Step "Terminating stale backend PID(s): $($stale.ProcessId -join ', ')"
        $parents = @($stale | Where-Object { $_.CommandLine -match 'app\.main:app' })
        $children = @($stale | Where-Object { $parents.ProcessId -notcontains $_.ProcessId })
        foreach ($c in $children) { Stop-Process -Id $c.ProcessId -Force -ErrorAction SilentlyContinue }
        foreach ($p in $parents)  { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
    }

    # --- 3. Wait until port released ---
    if (-not (Wait-PortFree $Port 15)) {
        $o = Get-PortOwnerPid $Port
        Write-Err "Port $Port is still occupied after kill (PID $o)."
        Write-Err 'Check for a stubborn process: netstat -ano | findstr :8000'
        exit 1
    }
    Write-Ok "Port $Port released."

    # --- 4. Start uvicorn ---
    $pythonExe = Get-PythonExe
    $uvicornArgs = @('-m', 'uvicorn', $AppString, '--host', $HostAddr, '--port', "$Port")
    if ($Reload) { $uvicornArgs += '--reload' }
    Write-Step "Starting: $pythonExe $($uvicornArgs -join ' ')  (workdir: $BackendDir)"

    if ($Foreground) {
        Push-Location $BackendDir
        & $pythonExe @uvicornArgs
        Pop-Location
        exit $LASTEXITCODE
    }

    $proc = Start-Process -FilePath $pythonExe -ArgumentList $uvicornArgs `
                          -WorkingDirectory $BackendDir -WindowStyle Normal -PassThru
    Write-Ok "Started backend process PID $($proc.Id)."

    # --- 5. Health check ---
    Write-Step "Waiting for http://localhost:8000/docs to return 200 (up to ${WaitSeconds}s)..."
    $healthy = $false
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            # Long per-request timeout: the very first request after a cold
            # start can take several seconds (lazy imports, DB pool init).
            $resp = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 20 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) { $healthy = $true; break }
        }
        catch { Start-Sleep -Milliseconds 700 }
    }

    if ($healthy) {
        $newOwner = Get-PortOwnerPid $Port
        Write-Host ''
        Write-Ok "Backend is healthy - PID $newOwner listening on port $Port"
        Write-Ok "API docs:  $HealthUrl"
        Write-Ok "Health:    http://localhost:$Port/api/v1/health"
        Write-Host ''
        Write-Host "Stop it later with:  .\start_backend.ps1 -Stop" -ForegroundColor Yellow
    }
    else {
        Show-FailureDiagnostics $Port
        Write-Host 'Check the backend console window (kept open) for the startup traceback.' -ForegroundColor Yellow
        exit 1
    }
}
catch {
    Write-Err "Unexpected error: $($_.Exception.Message)"
    Write-Host 'Diagnostics: check port ownership, firewall, permissions as described in docs/START_BACKEND.md' -ForegroundColor Yellow
    exit 1
}
