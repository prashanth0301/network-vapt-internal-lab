from typing import Optional

from fastapi import APIRouter, Depends
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.models.setting import Setting
from app.schemas.common import SuccessResponse

router = APIRouter(prefix="/settings", tags=["Settings"])

DEFAULT_SETTINGS: list[dict] = [
    {"key": "target_subnet", "value": "192.168.56.0/24", "category": "network", "description": "Default target subnet for scans"},
    {"key": "exclude_hosts", "value": "", "category": "network", "description": "Comma-separated hosts to exclude from scans"},
    {"key": "scan_interface", "value": "eth0", "category": "network", "description": "Network interface used for scanning"},
    {"key": "ping_sweep_type", "value": "ICMP Echo (-sn)", "category": "network", "description": "Ping sweep method"},
    {"key": "nmap_timing_template", "value": "T3", "category": "scanner", "description": "Nmap timing template"},
    {"key": "max_port_scan_rate", "value": "1000", "category": "scanner", "description": "Maximum packets per second during port scans"},
    {"key": "vulnerability_scanner", "value": "OpenVAS", "category": "scanner", "description": "Active vulnerability scanner"},
    {"key": "cve_database", "value": "NVD (Online)", "category": "scanner", "description": "CVE intelligence source"},
    {"key": "nmap_path", "value": "nmap", "category": "tools", "description": "Nmap executable path"},
    {"key": "tshark_path", "value": "tshark", "category": "tools", "description": "TShark executable path"},
    {"key": "msf_rpc_host", "value": "127.0.0.1:55553", "category": "tools", "description": "Metasploit RPC endpoint"},
    {"key": "openvas_socket", "value": "/var/run/openvassd.sock", "category": "tools", "description": "OpenVAS manager socket"},
]


class SettingsUpdate(BaseModel):
    values: dict[str, str] = Field(default_factory=dict, description="Key/value pairs to save")


@router.get("", response_model=SuccessResponse[list[dict]])
async def list_settings(
    category: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Setting)
    if category:
        query = query.where(Setting.category == category)
    result = await db.execute(query.order_by(Setting.category, Setting.key))
    rows = result.scalars().all()
    stored = {s.key: s for s in rows}

    items = []
    for default in DEFAULT_SETTINGS:
        if category and default["category"] != category:
            continue
        stored_row = stored.get(default["key"])
        items.append({
            "key": default["key"],
            "value": stored_row.value if stored_row else default["value"],
            "category": default["category"],
            "description": default["description"],
        })
    for s in rows:
        if s.key not in {d["key"] for d in DEFAULT_SETTINGS}:
            items.append({
                "key": s.key,
                "value": s.value,
                "category": s.category,
                "description": s.description,
            })
    return SuccessResponse(data=items, message=f"Found {len(items)} settings")


@router.put("", response_model=SuccessResponse[dict])
async def update_settings(
    body: SettingsUpdate,
    db: AsyncSession = Depends(get_db),
):
    if not body.values:
        return SuccessResponse(data={"updated": 0}, message="No settings provided")

    updated = 0
    for key, value in body.values.items():
        if value is None:
            value = ""
        result = await db.execute(select(Setting).where(Setting.key == key))
        row = result.scalar_one_or_none()
        if row:
            row.value = value
        else:
            row = Setting(key=key, value=value, category="custom")
            db.add(row)
        updated += 1
    await db.commit()
    logger.info("Settings updated: {count} keys", count=updated)
    return SuccessResponse(data={"updated": updated}, message=f"Saved {updated} settings")


@router.post("/reset", response_model=SuccessResponse[dict])
async def reset_settings(
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Setting))
    for row in result.scalars().all():
        default = next((d for d in DEFAULT_SETTINGS if d["key"] == row.key), None)
        if default:
            row.value = default["value"]
    await db.commit()
    return SuccessResponse(data={"reset": True}, message="Settings reset to defaults")
