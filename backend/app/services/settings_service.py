"""Settings service.

Defines the platform settings registry (key/category/type/validation), a
database-backed key/value store with typed validation, startup seeding,
logo file management and live system information collection.
"""

import os
import platform
import re
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import async_session_factory
from app.models.setting import Setting
from app.schemas.setting import (
    ContainerHealth,
    DatabaseStatus,
    DiskUsage,
    DockerStatus,
    MemoryInfo,
    NmapInfo,
    SettingItem,
    SystemInfoResponse,
    VersionInfo,
)

FRONTEND_VERSION = "1.0.0"

TIMEZONES = [
    "UTC",
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Los_Angeles",
    "America/Phoenix",
    "America/Anchorage",
    "America/Toronto",
    "America/Mexico_City",
    "America/Sao_Paulo",
    "America/Bogota",
    "America/Argentina/Buenos_Aires",
    "Europe/London",
    "Europe/Paris",
    "Europe/Berlin",
    "Europe/Madrid",
    "Europe/Rome",
    "Europe/Amsterdam",
    "Europe/Brussels",
    "Europe/Vienna",
    "Europe/Warsaw",
    "Europe/Prague",
    "Europe/Stockholm",
    "Europe/Oslo",
    "Europe/Copenhagen",
    "Europe/Helsinki",
    "Europe/Athens",
    "Europe/Istanbul",
    "Europe/Moscow",
    "Europe/Dublin",
    "Europe/Lisbon",
    "Europe/Zurich",
    "Europe/Bucharest",
    "Europe/Kyiv",
    "Africa/Cairo",
    "Africa/Johannesburg",
    "Africa/Lagos",
    "Africa/Nairobi",
    "Africa/Casablanca",
    "Asia/Dubai",
    "Asia/Riyadh",
    "Asia/Karachi",
    "Asia/Kolkata",
    "Asia/Dhaka",
    "Asia/Bangkok",
    "Asia/Singapore",
    "Asia/Hong_Kong",
    "Asia/Shanghai",
    "Asia/Tokyo",
    "Asia/Seoul",
    "Asia/Taipei",
    "Asia/Jakarta",
    "Asia/Manila",
    "Asia/Kuala_Lumpur",
    "Asia/Tehran",
    "Asia/Jerusalem",
    "Asia/Beirut",
    "Australia/Sydney",
    "Australia/Melbourne",
    "Australia/Brisbane",
    "Australia/Perth",
    "Australia/Adelaide",
    "Pacific/Auckland",
    "Pacific/Honolulu",
    "Pacific/Guam",
    "Pacific/Fiji",
]

SCAN_SPEEDS = ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"]
THEMES = ["light", "dark", "system"]
REPORT_TYPES = ["executive", "technical", "compliance"]
PDF_THEMES = ["modern", "classic", "minimal"]
PASSWORD_POLICIES = ["basic", "standard", "strong"]

PORT_RANGE_RE = re.compile(r"^(\d+(-\d+)?)(,\d+(-\d+)?)*$")

SettingDef = Dict[str, Any]

SETTING_DEFS: List[SettingDef] = [
    {
        "key": "general.organization_name",
        "category": "general",
        "type": "string",
        "default": "Network VAPT Lab",
        "max_length": 100,
        "description": "Organization name used across the platform",
    },
    {
        "key": "general.company_logo",
        "category": "general",
        "type": "string",
        "default": "",
        "max_length": 300,
        "description": "Uploaded company logo (used in the header and reports)",
    },
    {
        "key": "general.timezone",
        "category": "general",
        "type": "enum",
        "default": "UTC",
        "options": TIMEZONES,
        "description": "Default timezone for reports and timestamps",
    },
    {
        "key": "general.theme",
        "category": "general",
        "type": "enum",
        "default": "system",
        "options": THEMES,
        "description": "Default UI theme",
    },
    {
        "key": "scanner.default_scan_speed",
        "category": "scanner",
        "type": "enum",
        "default": "normal",
        "options": SCAN_SPEEDS,
        "description": "Default scan speed (nmap timing template)",
    },
    {
        "key": "scanner.default_port_range",
        "category": "scanner",
        "type": "string",
        "default": "1-1024",
        "max_length": 100,
        "description": "Default port range (e.g. 1-1024, 80,443)",
    },
    {
        "key": "scanner.enable_udp_scan",
        "category": "scanner",
        "type": "boolean",
        "default": "false",
        "description": "Enable UDP port scanning",
    },
    {
        "key": "scanner.enable_os_detection",
        "category": "scanner",
        "type": "boolean",
        "default": "true",
        "description": "Enable remote OS detection",
    },
    {
        "key": "scanner.enable_service_detection",
        "category": "scanner",
        "type": "boolean",
        "default": "true",
        "description": "Enable service/version detection",
    },
    {
        "key": "scanner.enable_banner_grabbing",
        "category": "scanner",
        "type": "boolean",
        "default": "true",
        "description": "Enable banner grabbing",
    },
    {
        "key": "scanner.nmap_path",
        "category": "scanner",
        "type": "string",
        "default": None,
        "max_length": 500,
        "description": "Nmap executable path (auto-detected)",
    },
    {
        "key": "reporting.default_report_type",
        "category": "reporting",
        "type": "enum",
        "default": "technical",
        "options": REPORT_TYPES,
        "description": "Default report type for generation",
    },
    {
        "key": "reporting.company_logo",
        "category": "reporting",
        "type": "string",
        "default": "",
        "max_length": 300,
        "description": "Company logo used in generated reports",
    },
    {
        "key": "reporting.watermark",
        "category": "reporting",
        "type": "string",
        "default": "",
        "max_length": 200,
        "description": "Watermark text stamped on report pages",
    },
    {
        "key": "reporting.footer_text",
        "category": "reporting",
        "type": "string",
        "default": "",
        "max_length": 300,
        "description": "Footer text shown on every report page",
    },
    {
        "key": "reporting.pdf_theme",
        "category": "reporting",
        "type": "enum",
        "default": "modern",
        "options": PDF_THEMES,
        "description": "PDF visual theme",
    },
    {
        "key": "security.session_timeout_minutes",
        "category": "security",
        "type": "integer",
        "default": "30",
        "min": 5,
        "max": 1440,
        "description": "Inactivity session timeout (minutes)",
    },
    {
        "key": "security.jwt_expiration_minutes",
        "category": "security",
        "type": "integer",
        "default": "30",
        "min": 5,
        "max": 10080,
        "description": "JWT token lifetime (minutes)",
    },
    {
        "key": "security.password_policy",
        "category": "security",
        "type": "enum",
        "default": "standard",
        "options": PASSWORD_POLICIES,
        "description": "Password complexity policy",
    },
    {
        "key": "security.max_login_attempts",
        "category": "security",
        "type": "integer",
        "default": "5",
        "min": 1,
        "max": 20,
        "description": "Maximum failed login attempts before lockout",
    },
]

REGISTRY: Dict[str, SettingDef] = {d["key"]: d for d in SETTING_DEFS}

MEDIA_DIR = Path(__file__).resolve().parents[2] / "media"
LOGO_DIR = MEDIA_DIR / "logos"

ALLOWED_LOGO_TYPES = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/webp": "webp",
    "image/svg+xml": "svg",
}
MAX_LOGO_BYTES = 2 * 1024 * 1024

LOGO_SETTING_KEYS = ("general.company_logo", "reporting.company_logo")


class SettingsValidationError(Exception):
    """Raised when one or more setting values fail validation."""

    def __init__(self, message: str, details: Optional[Dict[str, str]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


def detect_nmap_path() -> str:
    """Return the auto-detected nmap executable path."""
    return shutil.which("nmap") or "nmap"


def _default_value(defn: SettingDef) -> str:
    if defn["key"] == "scanner.nmap_path":
        return detect_nmap_path()
    return str(defn.get("default", ""))


def _validate_port_range(value: str) -> Optional[str]:
    if not PORT_RANGE_RE.match(value):
        return "must be a comma-separated list of ports or ranges (e.g. 1-1024, 80,443)"
    for part in value.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
        else:
            lo = hi = part
        try:
            lo_n, hi_n = int(lo), int(hi)
        except ValueError:
            return f"'{part}' is not a valid port"
        if not (1 <= lo_n <= 65535 and 1 <= hi_n <= 65535):
            return f"'{part}' is outside the valid port range 1-65535"
        if lo_n > hi_n:
            return f"range '{part}' has a lower bound greater than its upper bound"
    return None


def validate_value(defn: SettingDef, value: str) -> Optional[str]:
    """Validate a raw string value against a setting definition."""
    value_type = defn.get("type", "string")
    if value_type == "boolean":
        if value not in ("true", "false"):
            return "must be 'true' or 'false'"
    elif value_type == "integer":
        try:
            num = int(value)
        except ValueError:
            return "must be a whole number"
        lo = defn.get("min")
        hi = defn.get("max")
        if lo is not None and num < lo:
            return f"must be at least {lo}"
        if hi is not None and num > hi:
            return f"must be at most {hi}"
    elif value_type == "enum":
        options = defn.get("options") or []
        if value not in options:
            if defn["key"] == "general.timezone":
                return "must be one of the supported timezones (e.g. UTC, Asia/Kolkata)"
            return f"must be one of: {', '.join(options)}"
    else:  # string
        max_length = defn.get("max_length")
        if max_length and len(value) > max_length:
            return f"must be at most {max_length} characters"

    if defn["key"] == "scanner.default_port_range":
        return _validate_port_range(value.replace(" ", ""))
    return None


def _build_item(defn: SettingDef, value: str, readonly: bool = False) -> SettingItem:
    return SettingItem(
        key=defn["key"],
        value=value,
        category=defn["category"],
        description=defn.get("description", ""),
        type=defn.get("type", "string"),
        options=list(defn["options"]) if defn.get("options") else None,
        min=defn.get("min"),
        max=defn.get("max"),
        readonly=readonly,
    )


async def get_settings(
    session: AsyncSession, category: Optional[str] = None
) -> List[SettingItem]:
    """Return settings merged with defaults (stored values win)."""
    result = await session.execute(select(Setting))
    stored = {s.key: s for s in result.scalars().all()}

    detected_nmap = detect_nmap_path()
    items: List[SettingItem] = []
    for defn in SETTING_DEFS:
        if category and defn["category"] != category:
            continue
        row = stored.get(defn["key"])
        value = row.value if row and row.value is not None else _default_value(defn)
        readonly = False
        if defn["key"] == "scanner.nmap_path":
            readonly = value == detected_nmap
        items.append(_build_item(defn, value, readonly=readonly))

    for row in stored.values():
        if row.key in REGISTRY:
            continue
        if category and row.category != category:
            continue
        items.append(
            SettingItem(
                key=row.key,
                value=row.value or "",
                category=row.category or "custom",
                description=row.description or row.key,
                type="string",
            )
        )
    return items


async def save_settings(session: AsyncSession, values: Dict[str, str]) -> int:
    """Validate and persist the given settings. Raises SettingsValidationError."""
    errors: Dict[str, str] = {}
    valid: List[Tuple[str, str]] = []
    for key, value in values.items():
        if value is None:
            value = ""
        defn = REGISTRY.get(key)
        if defn is None:
            errors[key] = "unknown setting key"
            continue
        error = validate_value(defn, value)
        if error:
            errors[key] = error
        else:
            valid.append((key, value))

    if errors:
        raise SettingsValidationError(
            "One or more settings failed validation", details=errors
        )

    updated = 0
    for key, value in valid:
        result = await session.execute(select(Setting).where(Setting.key == key))
        row = result.scalar_one_or_none()
        if row:
            row.value = value
        else:
            row = Setting(key=key, value=value, category=REGISTRY[key]["category"])
            session.add(row)
        updated += 1
    await session.flush()
    return updated


async def reset_settings(session: AsyncSession) -> int:
    """Restore all registered settings to their default values."""
    result = await session.execute(select(Setting))
    reset = 0
    for row in result.scalars().all():
        defn = REGISTRY.get(row.key)
        if defn:
            row.value = _default_value(defn)
            reset += 1
    await session.flush()
    return reset


async def seed_default_settings() -> int:
    """Insert missing default settings (idempotent, preserves user values)."""
    async with async_session_factory() as session:
        result = await session.execute(select(Setting.key))
        existing = set(result.scalars().all())
        seeded = 0
        for defn in SETTING_DEFS:
            if defn["key"] not in existing:
                session.add(
                    Setting(
                        key=defn["key"],
                        value=_default_value(defn),
                        category=defn["category"],
                        description=defn.get("description", ""),
                    )
                )
                seeded += 1
        await session.commit()
    return seeded


# ---------------------------------------------------------------------------
# Logo management
# ---------------------------------------------------------------------------


def _safe_logo_filename(value: str) -> Optional[Path]:
    if not value:
        return None
    if "/" in value or "\\" in value or ".." in value or value != Path(value).name:
        return None
    path = LOGO_DIR / value
    return path if path.is_file() else None


def resolve_logo_path(stored_value: str) -> Optional[Path]:
    return _safe_logo_filename(stored_value)


async def upload_logo(
    session: AsyncSession, content: bytes, content_type: str, original_name: str
) -> str:
    """Validate, persist and register a company logo file."""
    if content_type not in ALLOWED_LOGO_TYPES:
        raise SettingsValidationError(
            f"Unsupported file type '{content_type or 'unknown'}'. "
            f"Allowed: PNG, JPEG, WebP, SVG"
        )
    if len(content) > MAX_LOGO_BYTES:
        raise SettingsValidationError(
            f"Logo file exceeds the 2 MB limit ({len(content)} bytes)"
        )
    if len(content) == 0:
        raise SettingsValidationError("Logo file is empty")

    LOGO_DIR.mkdir(parents=True, exist_ok=True)
    ext = ALLOWED_LOGO_TYPES[content_type]
    filename = f"{uuid.uuid4().hex}.{ext}"
    dest = LOGO_DIR / filename
    dest.write_bytes(content)

    result = await session.execute(
        select(Setting).where(Setting.key == "general.company_logo")
    )
    old_row = result.scalar_one_or_none()
    old_value = old_row.value if old_row else None
    previous = _safe_logo_filename(old_value or "") if old_value else None

    for key in LOGO_SETTING_KEYS:
        result = await session.execute(select(Setting).where(Setting.key == key))
        row = result.scalar_one_or_none()
        if row:
            row.value = filename
        else:
            session.add(Setting(key=key, value=filename, category=key.split(".")[0]))
    await session.flush()

    if previous and previous.name != filename:
        try:
            previous.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not remove previous logo {path}: {err}", path=previous, err=exc)
    return filename


async def remove_logo(session: AsyncSession) -> None:
    result = await session.execute(
        select(Setting).where(Setting.key == "general.company_logo")
    )
    row = result.scalar_one_or_none()
    previous = _safe_logo_filename(row.value) if row and row.value else None
    if previous:
        try:
            previous.unlink(missing_ok=True)
        except OSError as exc:
            logger.warning("Could not remove logo {path}: {err}", path=previous, err=exc)

    for key in LOGO_SETTING_KEYS:
        result = await session.execute(select(Setting).where(Setting.key == key))
        row = result.scalar_one_or_none()
        if row:
            row.value = ""
    await session.flush()


# ---------------------------------------------------------------------------
# System information
# ---------------------------------------------------------------------------


def _read_lines(path: str, limit: int = 100) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.readlines(limit)
    except OSError:
        return []


def _is_running_in_container() -> bool:
    if os.path.exists("/.dockerenv"):
        return True
    try:
        lines = _read_lines("/proc/1/cgroup")
        return any("docker" in line or "kubepods" in line for line in lines)
    except Exception:
        return False


def _nmap_version(path: str) -> str:
    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        first_line = (proc.stdout or "").strip().splitlines()
        return first_line[0] if first_line else "Unknown"
    except FileNotFoundError:
        return "Not installed"
    except (OSError, subprocess.SubprocessError):
        return "Unavailable"


def _disk_usage() -> DiskUsage:
    try:
        usage = shutil.disk_usage("/")
        total_gb = round(usage.total / (1024**3), 2)
        used_gb = round(usage.used / (1024**3), 2)
        free_gb = round(usage.free / (1024**3), 2)
        percent = round(usage.used / usage.total * 100, 1) if usage.total else 0.0
        return DiskUsage(
            total_gb=total_gb, used_gb=used_gb, free_gb=free_gb, percent=percent
        )
    except OSError:
        return DiskUsage(total_gb=0.0, used_gb=0.0, free_gb=0.0, percent=0.0)


def _uptime_seconds() -> Optional[int]:
    try:
        line = _read_lines("/proc/uptime", 1)
        if line:
            return int(float(line[0].split()[0]))
    except (ValueError, IndexError):
        pass
    return None


def _memory_info() -> Optional[MemoryInfo]:
    meminfo: Dict[str, float] = {}
    for line in _read_lines("/proc/meminfo", 32):
        parts = line.split(":")
        if len(parts) == 2 and parts[0] in ("MemTotal", "MemAvailable"):
            try:
                meminfo[parts[0]] = float(parts[1].strip().split()[0]) / (1024**2)
            except (ValueError, IndexError):
                pass
    if "MemTotal" not in meminfo:
        return None
    available = meminfo.get("MemAvailable", meminfo["MemTotal"])
    return MemoryInfo(
        total_gb=round(meminfo["MemTotal"], 2),
        available_gb=round(available, 2),
    )


async def _database_status() -> DatabaseStatus:
    start = time.perf_counter()
    try:
        async with async_session_factory() as session:
            await session.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return DatabaseStatus(connected=True, latency_ms=latency_ms)
    except Exception as exc:
        logger.warning("Database health check failed: {err}", err=exc)
        return DatabaseStatus(connected=False, latency_ms=None)


async def get_system_info() -> SystemInfoResponse:
    """Collect live system information without ever raising."""
    in_container = _is_running_in_container()
    docker_status = DockerStatus(
        in_container=in_container,
        mode="docker" if in_container else "bare-metal",
        container_name=socket.gethostname() if in_container else None,
    )

    database = await _database_status()

    nmap_path = detect_nmap_path()
    nmap = NmapInfo(path=nmap_path, version=_nmap_version(nmap_path))

    disk = _disk_usage()
    memory = _memory_info()
    uptime = _uptime_seconds()

    components = {
        "app": "ok",
        "database": "ok" if database.connected else "error",
        "disk": "ok" if disk.percent < 90 else "warning",
    }
    health_status = (
        "healthy"
        if all(v == "ok" for v in components.values())
        else "degraded"
    )
    health = ContainerHealth(
        status=health_status,
        components=components,
        uptime_seconds=uptime,
        memory=memory,
        python_version=platform.python_version(),
    )

    return SystemInfoResponse(
        docker=docker_status,
        database=database,
        backend=VersionInfo(name="backend", version=settings.APP_VERSION),
        frontend=VersionInfo(name="frontend", version=FRONTEND_VERSION),
        nmap=nmap,
        disk=disk,
        health=health,
    )
