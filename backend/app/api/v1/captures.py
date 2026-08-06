import asyncio
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, UploadFile, File
from fastapi.responses import FileResponse
from loguru import logger
from sqlalchemy import cast, func, or_, select, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.services.auth import get_current_user
from app.models.packet import Conversation, Packet
from app.models.packet_capture import PacketCapture
from app.schemas.common import SuccessResponse
from app.services.pcap_parser import PcapParseError, parse_capture_file

router = APIRouter(
    prefix="/captures",
    tags=["Packet Captures"],
    dependencies=[Depends(get_current_user)],
)

ACTIVE_CAPTURES: dict[str, dict] = {}

PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")

MAX_UPLOAD_SIZE = 50 * 1024 * 1024

# Order matters: dumpcap is preferred (single process, no child tools),
# tshark is the fallback, tcpdump last.
_CAPTURE_TOOLS = ("dumpcap", "tshark", "tcpdump")


def _candidate_tool_dirs() -> list[Path]:
    from app.core.config import settings

    dirs = [Path(r"C:\Program Files\Wireshark"), Path(r"C:\Program Files (x86)\Wireshark")]
    env_dir = os.environ.get("WIRESHARK_DIR", "").strip()
    if env_dir:
        dirs.insert(0, Path(env_dir))
    dirs.append(settings.BASE_DIR.parent.parent / "VAPT-tools" / "wireshark")
    return dirs


def _find_capture_tool() -> tuple[Optional[str], Optional[str]]:
    """Return (tool_path, tool_kind) where tool_kind in {dumpcap, tshark, tcpdump}."""
    for tool in _CAPTURE_TOOLS:
        found = shutil.which(tool)
        if found:
            return found, tool
        for d in _candidate_tool_dirs():
            exe = d / f"{tool}.exe"
            if exe.exists():
                return str(exe), tool
    return None, None


def _scapy_capture_available() -> bool:
    """True when the Scapy package is importable (used as the capture backend
    when no external capture tool is installed)."""
    try:
        import scapy.all as scapy  # noqa: F401
        return True
    except ImportError:
        return False


def _npcap_installed() -> bool:
    return any(
        Path(p).exists()
        for p in (
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\System32\wpcap.dll",
            r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
        )
    )


def _psutil_interfaces() -> dict:
    """Enumerate interfaces via psutil, keyed by friendly name.

    Returns {name: {"ip_address", "mac_address", "status"}} where status is
    "up"/"down". Falls back to {} when psutil is unavailable.
    """
    try:
        import psutil
    except ImportError:
        return {}
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except Exception:
        return {}
    af_inet = getattr(socket, "AF_INET", None)
    af_link = getattr(psutil, "AF_LINK", None)
    result: dict = {}
    for name, ifaddrs in addrs.items():
        ip = mac = None
        for a in ifaddrs:
            if af_inet is not None and a.family == af_inet:
                ip = a.address
            elif af_link is not None and a.family == af_link:
                mac = a.address
        st = stats.get(name)
        if ip in ("0.0.0.0", "", None):
            ip = None
        if mac in ("00:00:00:00:00:00", "", None):
            mac = None
        result[name] = {
            "ip_address": ip,
            "mac_address": mac,
            "status": "up" if (st is not None and st.isup) else "down",
        }
    return result


def _scapy_interfaces() -> dict:
    """Enumerate interfaces via Scapy, keyed by capture device id.

    On Windows the device ids are \\Device\\NPF_... names (identical to
    `dumpcap -D` ids); on Linux they are lo/eth0 etc. Returns
    {id: {"ip_address", "mac_address"}}, or {} when Scapy is unavailable.
    """
    try:
        import scapy.all as scapy
    except ImportError:
        return {}
    try:
        devices = scapy.get_if_list()
    except Exception:
        return {}
    result: dict = {}
    for dev in devices:
        ip = mac = None
        try:
            ip = scapy.get_if_addr(dev)
        except Exception:
            pass
        try:
            mac = scapy.get_if_hwaddr(dev)
        except Exception:
            pass
        if ip in ("0.0.0.0", "", None):
            ip = None
        if mac in ("00:00:00:00:00:00", "", None):
            mac = None
        result[dev] = {"ip_address": ip, "mac_address": mac}
    return result


def _enrich_interfaces(items: list[dict], scapy_map: dict, psutil_map: dict) -> list[dict]:
    """Attach ip_address/mac_address/status to interface descriptors.

    Scapy metadata is matched by capture device id; psutil metadata is matched
    by friendly name/description. Scapy IPs are preferred because they are
    bound to the exact capture device.
    """
    for item in items:
        meta = scapy_map.get(item["id"])
        item["ip_address"] = meta.get("ip_address") if meta else None
        item["mac_address"] = meta.get("mac_address") if meta else None
        item["status"] = "unknown"
        ps = psutil_map.get(item["description"]) or psutil_map.get(item["name"])
        if ps:
            item["ip_address"] = item["ip_address"] or ps.get("ip_address")
            item["mac_address"] = item["mac_address"] or ps.get("mac_address")
            item["status"] = ps.get("status") or item["status"]
    return items


def _list_interfaces_fallback() -> list[dict]:
    """Enumerate interfaces without a capture tool using Scapy/psutil."""
    scapy_map = _scapy_interfaces()
    psutil_map = _psutil_interfaces()
    by_ip: dict = {}
    for name, ps in psutil_map.items():
        if ps.get("ip_address"):
            by_ip.setdefault(ps["ip_address"], name)
    items: list[dict] = []
    for dev, meta in scapy_map.items():
        ps = psutil_map.get(dev)
        friendly = dev
        if ps:
            friendly = dev
        elif meta.get("ip_address") and meta["ip_address"] in by_ip:
            friendly = by_ip[meta["ip_address"]]
        ps = psutil_map.get(friendly)
        items.append(
            {
                "id": dev,
                "name": friendly,
                "description": friendly,
                "ip_address": meta.get("ip_address") or (ps or {}).get("ip_address"),
                "mac_address": meta.get("mac_address") or (ps or {}).get("mac_address"),
                "status": (ps or {}).get("status", "unknown"),
            }
        )
    used = {i["id"] for i in items}
    used.update(i["description"] for i in items)
    for name, ps in psutil_map.items():
        if name in used:
            continue
        items.append(
            {
                "id": name,
                "name": name,
                "description": name,
                "ip_address": ps.get("ip_address"),
                "mac_address": ps.get("mac_address"),
                "status": ps.get("status", "unknown"),
            }
        )
    return items


def _no_capture_tool_message() -> str:
    if not _npcap_installed():
        return (
            "Live capture requires the Npcap driver and a capture tool (dumpcap or tshark from Wireshark). "
            "Npcap was not detected on this machine - install Npcap from https://npcap.com, then install "
            "Wireshark or place dumpcap.exe/tshark.exe in a Wireshark install directory. "
            "Uploading a PCAP file still works."
        )
    return (
        "Live capture requires a capture tool (dumpcap or tshark from Wireshark, or tcpdump) or the "
        "Python Scapy package on the server. Install Wireshark from https://www.wireshark.org, set "
        "WIRESHARK_DIR to its install folder, or install the backend dependencies (scapy) and retry. "
        "Uploading a PCAP file still works."
    )


def _list_interfaces(tool_path: str) -> list[dict]:
    """Parse `dumpcap -D` / `tshark -D` output into interface descriptors,
    enriched with ip_address/mac_address/status where available."""
    try:
        result = subprocess.run(
            [tool_path, "-D"], capture_output=True, text=True, timeout=20
        )
    except Exception as e:
        logger.warning("Interface enumeration failed: {error}", error=str(e))
        return []
    items = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(\d+)\.\s+(.+?)\s+\((.+)\)\s*$", line)
        if m:
            name = m.group(2).strip()
            description = m.group(3).strip()
        else:
            m2 = re.match(r"^(\d+)\.\s+(.+)$", line)
            if not m2:
                continue
            name = m2.group(2).strip()
            description = ""
        items.append({"id": name, "name": name, "description": description})
    if not items:
        return items
    return _enrich_interfaces(items, _scapy_interfaces(), _psutil_interfaces())


def _default_interface(tool_path: str) -> Optional[str]:
    """Pick a sensible default: the Npcap loopback adapter (localhost traffic)
    when available, otherwise the first enumerated interface."""
    interfaces = _list_interfaces(tool_path)
    if not interfaces:
        return None
    for iface in interfaces:
        if "loopback" in iface["id"].lower() or "loopback" in iface["description"].lower():
            return iface["id"]
    return interfaces[0]["id"]


def _is_loopback_interface(item: dict) -> bool:
    """True when an interface descriptor refers to a loopback adapter.

    Handles both the Windows NPF_Loopback device id and the Linux `lo`
    interface, and matches by loopback-assigned addresses as a fallback.
    """
    ident = (item.get("id") or "").lower()
    name = (item.get("name") or "").lower()
    desc = (item.get("description") or "").lower()
    ip = item.get("ip_address") or ""
    return (
        "loopback" in ident
        or "loopback" in name
        or "loopback" in desc
        or ident == "lo"
        or name == "lo"
        or ip in ("127.0.0.1", "::1")
    )


def _default_interface_scapy() -> Optional[str]:
    """Pick a sensible default when capturing via Scapy.

    Prefers the first non-loopback interface that is UP (e.g. `eth0` inside
    Docker), then any other non-loopback interface, and only falls back to the
    loopback adapter (lo / NPF_Loopback) when no other interface exists.
    """
    items = _list_interfaces_fallback()
    if not items:
        return None
    usable = [i for i in items if not _is_loopback_interface(i)]
    if usable:
        for item in usable:
            if item.get("status") == "up":
                return item["id"]
        return usable[0]["id"]
    return items[0]["id"]


def _scapy_capture_worker(
    iface: str, dest_path: Path, filter_expr: Optional[str], state: dict
) -> None:
    """Capture with Scapy into a classic pcap file. Runs in a daemon thread.

    Uses scapy.sniff() in short timed slices so the loop can exit promptly when
    `state["stop"]` is set (stop_filter alone would block forever on a quiet
    interface). Packets are appended to a PcapWriter with sync=True so the file
    grows live and status polling can report the current byte size.
    """
    from scapy.all import PcapWriter, sniff

    writer = None
    try:
        writer = PcapWriter(str(dest_path), linktype=1, sync=True)

        def on_pkt(pkt):
            try:
                writer.write(pkt)
                state["count"] = state.get("count", 0) + 1
            except Exception as e:
                state["error"] = f"Scapy packet write failed: {e}"
                state["stop"] = True

        while not state.get("stop"):
            try:
                sniff(
                    iface=iface,
                    prn=on_pkt,
                    store=False,
                    count=0,
                    timeout=0.5,
                    filter=filter_expr,
                )
            except Exception as e:
                # A BPF filter may be unsupported on the local platform; retry
                # without it before giving up.
                if filter_expr and not state.get("filter_disabled"):
                    logger.warning(
                        "Scapy BPF filter unsupported on interface {iface}, retrying without filter: {error}",
                        iface=iface,
                        error=str(e),
                    )
                    state["filter_disabled"] = True
                    filter_expr = None
                    continue
                state["error"] = str(e)
                state["stop"] = True
    except Exception as e:
        state["error"] = f"Scapy capture failed to start: {e}"
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


def _count_pcap_packets(path: Path) -> int:
    """Fast packet count for classic libpcap files by walking record headers."""
    try:
        with open(path, "rb") as f:
            head = f.read(24)
            if len(head) < 24:
                return 0
            magic = head[:4]
            if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
                endian = "<"
            elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                endian = ">"
            else:
                return 0
            count = 0
            while True:
                hdr = f.read(16)
                if len(hdr) < 16:
                    break
                incl_len = struct.unpack(f"{endian}I", hdr[8:12])[0]
                if incl_len > 16 * 1024 * 1024:
                    break
                f.seek(incl_len, 1)
                count += 1
            return count
    except OSError:
        pass
    return 0


def _capture_to_dict(c) -> dict:
    return {
        "id": str(c.id),
        "filename": c.filename,
        "size": _format_size(c.file_size),
        "packets": c.packet_count or 0,
        "duration": f"{c.duration_seconds or 0}s",
        "date": c.created_at.isoformat() if c.created_at else "",
        "status": "completed" if c.capture_ended_at else ("capturing" if c.capture_started_at else "pending"),
        "protocol_stats": c.protocol_stats or {},
        "total_bytes": c.total_bytes or 0,
        "avg_packet_size": c.avg_packet_size or 0.0,
        "packets_per_second": c.packets_per_second or 0.0,
        "scan_id": str(c.scan_id) if c.scan_id else None,
    }


@router.get("", response_model=SuccessResponse[list[dict]])
async def list_captures(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    search: Optional[str] = Query(None, description="Search captures by filename, status, or protocol"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    query = select(PacketCapture)
    if assessment_id:
        try:
            query = query.where(PacketCapture.scan_id == uuid.UUID(assessment_id))
        except ValueError:
            return SuccessResponse(data=[], message="Invalid assessment_id format")
    if search:
        term = f"%{search.strip()}%"
        query = query.where(or_(
            PacketCapture.filename.ilike(term),
            cast(PacketCapture.packet_count, String).ilike(term),
            cast(PacketCapture.file_size, String).ilike(term),
            cast(PacketCapture.protocol_stats, String).ilike(term),
            cast(PacketCapture.filter, String).ilike(term),
            cast(PacketCapture.created_at, String).ilike(term),
            func.to_char(PacketCapture.created_at, "Month").ilike(term),
            func.to_char(PacketCapture.created_at, "YYYY").ilike(term),
            cast(PacketCapture.capture_started_at, String).ilike(term),
            cast(PacketCapture.capture_ended_at, String).ilike(term),
        ))
    query = query.order_by(PacketCapture.created_at.desc()).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    captures = result.scalars().all()
    items = [_capture_to_dict(c) for c in captures]
    return SuccessResponse(data=items, message=f"Found {len(captures)} captures")


@router.get("/protocols", response_model=SuccessResponse[list[dict]])
async def get_protocol_stats(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    db: AsyncSession = Depends(get_db),
):
    query = select(PacketCapture)
    if assessment_id:
        try:
            query = query.where(PacketCapture.scan_id == uuid.UUID(assessment_id))
        except ValueError:
            return SuccessResponse(data=[], message="Invalid assessment_id format")
    query = query.order_by(PacketCapture.created_at.desc()).limit(50)
    result = await db.execute(query)
    captures = result.scalars().all()

    from collections import Counter
    counter: Counter[str] = Counter()
    for c in captures:
        if c.protocol_stats:
            for proto, count in c.protocol_stats.items():
                if isinstance(count, (int, float)):
                    counter[proto] += int(count)

    total = sum(counter.values())
    if total <= 0:
        return SuccessResponse(data=[], message="No protocol data available")

    stats = [
        {"protocol": proto, "percentage": round((count / total) * 100, 1), "packets": count}
        for proto, count in counter.most_common()
    ]
    return SuccessResponse(data=stats, message="Protocol distribution")


@router.get("/interfaces", response_model=SuccessResponse[list[dict]])
async def list_capture_interfaces():
    """List capture interfaces available on the server.

    Uses `dumpcap -D` / `tshark -D` when a capture tool is present, otherwise
    falls back to system-level enumeration (Scapy/psutil).
    """
    tool, _ = _find_capture_tool()
    if tool:
        items = _list_interfaces(tool)
        if items:
            return SuccessResponse(data=items, message=f"Found {len(items)} interfaces")
    items = _list_interfaces_fallback()
    if items:
        return SuccessResponse(
            data=items,
            message=f"Found {len(items)} interfaces (system enumeration)",
        )
    if not _npcap_installed():
        return SuccessResponse(data=[], message=_no_capture_tool_message())
    return SuccessResponse(
        data=[],
        message="No capture interfaces found. Make sure the Npcap driver is installed and running.",
    )


@router.get("/{capture_id}", response_model=SuccessResponse[dict])
async def get_capture(capture_id: str, db: AsyncSession = Depends(get_db)):
    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        return SuccessResponse(data={}, message="Invalid capture ID format")
    result = await db.execute(select(PacketCapture).where(PacketCapture.id == uid))
    capture = result.scalar_one_or_none()
    if not capture:
        return SuccessResponse(data={}, message="Capture not found")

    conv_count = 0
    if capture.capture_ended_at:
        count_result = await db.execute(
            select(func.count()).select_from(Conversation).where(
                Conversation.capture_id == uid
            )
        )
        conv_count = count_result.scalar() or 0

    data = _capture_to_dict(capture)
    data["conversation_count"] = conv_count
    data["started_at"] = capture.capture_started_at.isoformat() if capture.capture_started_at else None
    data["ended_at"] = capture.capture_ended_at.isoformat() if capture.capture_ended_at else None
    return SuccessResponse(data=data, message="Capture retrieved")


@router.get("/{capture_id}/download")
async def download_capture(capture_id: str, db: AsyncSession = Depends(get_db)):
    """Stream the stored PCAP file for a capture as an attachment download.

    Returns 404 when the capture does not exist or its file is missing.
    Authentication is enforced by the router-level ``get_current_user``
    dependency (same as all other capture endpoints).
    """
    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Capture not found")

    result = await db.execute(select(PacketCapture).where(PacketCapture.id == uid))
    capture = result.scalar_one_or_none()
    if capture is None:
        raise HTTPException(status_code=404, detail="Capture not found")

    filepath = Path(capture.filepath)
    if not filepath.is_file() or filepath.stat().st_size <= 0:
        logger.info(
            "Capture download requested but file is missing: {id} ({path})",
            id=capture_id,
            path=capture.filepath,
        )
        raise HTTPException(status_code=404, detail="Capture file not found")

    return FileResponse(
        path=str(filepath),
        media_type="application/vnd.tcpdump.pcap",
        filename=capture.filename or f"live_{capture.id}.pcap",
    )


@router.delete("/{capture_id}", response_model=SuccessResponse[dict])
async def delete_capture(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: object = Depends(get_current_user),
):
    """Delete a capture and all associated packets, conversations, and PCAP file.

    Only administrators may delete captures.
    """
    from app.models.user import User as UserModel

    user: UserModel = current_user  # type: ignore[assignment]
    if user.role != "administrator":
        raise HTTPException(status_code=403, detail="Only administrators can delete captures")

    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid capture ID format")

    result = await db.execute(select(PacketCapture).where(PacketCapture.id == uid))
    capture = result.scalar_one_or_none()
    if not capture:
        raise HTTPException(status_code=404, detail="Capture not found")

    packet_result = await db.execute(
        select(Packet.id).where(Packet.capture_id == uid)
    )
    packet_ids = [row[0] for row in packet_result.all()]
    if packet_ids:
        await db.execute(
            Packet.__table__.delete().where(Packet.capture_id == uid)
        )

    conv_result = await db.execute(
        select(Conversation.id).where(Conversation.capture_id == uid)
    )
    conv_ids = [row[0] for row in conv_result.all()]
    if conv_ids:
        await db.execute(
            Conversation.__table__.delete().where(Conversation.capture_id == uid)
        )

    filepath = Path(capture.filepath)
    file_removed = False
    if filepath.is_file():
        try:
            filepath.unlink()
            file_removed = True
            logger.info("Capture file removed: {path}", path=filepath)
        except OSError as exc:
            logger.error("Failed to remove capture file {path}: {err}", path=filepath, err=exc)

    await db.execute(
        PacketCapture.__table__.delete().where(PacketCapture.id == uid)
    )
    await db.commit()

    logger.info(
        "Capture deleted: {id} by {user} (file_removed={file_removed})",
        id=capture_id,
        user=current_user.username,
        file_removed=file_removed,
    )
    return SuccessResponse(
        data={"id": capture_id, "packets_deleted": len(packet_ids), "conversations_deleted": len(conv_ids)},
        message="Capture deleted successfully",
    )


@router.get("/{capture_id}/packets", response_model=SuccessResponse[dict])
async def list_capture_packets(
    capture_id: str,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    protocol: Optional[str] = Query(None, description="Filter by protocol name"),
    db: AsyncSession = Depends(get_db),
):
    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        return SuccessResponse(data={"items": [], "total": 0}, message="Invalid capture ID format")

    exists = await db.execute(
        select(PacketCapture.id).where(PacketCapture.id == uid)
    )
    if exists.scalar_one_or_none() is None:
        return SuccessResponse(data={"items": [], "total": 0}, message="Capture not found")

    base = select(Packet).where(Packet.capture_id == uid)
    count_query = select(func.count()).select_from(Packet).where(Packet.capture_id == uid)
    if protocol:
        base = base.where(Packet.protocol == protocol)
        count_query = count_query.where(Packet.protocol == protocol)

    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0

    result = await db.execute(
        base.order_by(Packet.seq).offset((page - 1) * per_page).limit(per_page)
    )
    packets = result.scalars().all()
    items = [
        {
            "id": str(p.id),
            "seq": p.seq,
            "timestamp": p.timestamp.isoformat() if p.timestamp else None,
            "src_ip": p.src_ip,
            "dst_ip": p.dst_ip,
            "src_port": p.src_port,
            "dst_port": p.dst_port,
            "protocol": p.protocol,
            "length": p.length,
            "info": p.info,
        }
        for p in packets
    ]
    return SuccessResponse(
        data={"items": items, "total": total, "page": page, "per_page": per_page},
        message=f"Found {total} packets",
    )


@router.get("/{capture_id}/conversations", response_model=SuccessResponse[list[dict]])
async def list_capture_conversations(
    capture_id: str,
    db: AsyncSession = Depends(get_db),
):
    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        return SuccessResponse(data=[], message="Invalid capture ID format")

    result = await db.execute(
        select(Conversation)
        .where(Conversation.capture_id == uid)
        .order_by(Conversation.packets.desc())
    )
    conversations = result.scalars().all()
    items = [
        {
            "id": str(c.id),
            "src_ip": c.src_ip,
            "dst_ip": c.dst_ip,
            "src_port": c.src_port,
            "dst_port": c.dst_port,
            "protocol": c.protocol,
            "packets": c.packets,
            "bytes": c.bytes,
        }
        for c in conversations
    ]
    return SuccessResponse(data=items, message=f"Found {len(items)} conversations")


@router.post("/upload", response_model=SuccessResponse[dict])
async def upload_capture(
    file: UploadFile = File(...),
    assessment_id: Optional[str] = Form(None, description="Assessment UUID to associate with this capture"),
    db: AsyncSession = Depends(get_db),
):
    from app.core.config import settings

    capture_id = str(uuid.uuid4())
    original_name = file.filename or f"capture_{capture_id}.pcap"
    filename = original_name
    if not filename.lower().endswith(PCAP_EXTENSIONS):
        filename = f"{filename}.pcap"

    content = b""
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        content += chunk
        if len(content) > MAX_UPLOAD_SIZE:
            return SuccessResponse(
                data={},
                message=f"File exceeds the maximum allowed size of {MAX_UPLOAD_SIZE // (1024 * 1024)} MB",
            )

    if not content:
        return SuccessResponse(
            data={},
            message="Uploaded file is empty",
        )

    try:
        parsed = parse_capture_file(content)
    except PcapParseError as e:
        logger.warning("PCAP parse failed for {name}: {error}", name=original_name, error=str(e))
        return SuccessResponse(
            data={"id": capture_id, "filename": original_name, "error": str(e)},
            message=f"Capture upload failed: {e}",
        )

    dest_dir = settings.BASE_DIR / ".." / "captures"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / f"{capture_id}_{filename}"
    dest_path.write_bytes(content)

    scan_uuid = None
    if assessment_id:
        try:
            scan_uuid = uuid.UUID(assessment_id)
        except ValueError:
            scan_uuid = None

    capture = PacketCapture(
        id=uuid.UUID(capture_id),
        scan_id=scan_uuid,
        filename=original_name,
        filepath=str(dest_path),
        file_size=len(content),
        packet_count=parsed["packet_count"],
        duration_seconds=parsed["duration_seconds"],
        total_bytes=parsed["total_bytes"],
        avg_packet_size=parsed["avg_packet_size"],
        packets_per_second=parsed["packets_per_second"],
        protocol_stats=parsed["protocol_stats"],
        capture_started_at=_parse_dt(parsed["capture_started_at"]),
        capture_ended_at=_parse_dt(parsed["capture_ended_at"]),
    )
    db.add(capture)

    try:
        await db.flush()
        await _store_packets(db, capture.id, parsed["packets"])
        await _store_conversations(db, capture.id, parsed["conversations"])
        await db.commit()
    except Exception as e:
        await db.rollback()
        dest_path.unlink(missing_ok=True)
        logger.error("Failed to store capture {name}: {error}", name=original_name, error=str(e))
        return SuccessResponse(
            data={"id": capture_id, "filename": original_name, "error": str(e)},
            message=f"Capture analysis failed: {e}",
        )

    logger.info(
        "Capture uploaded and analyzed: {name} ({packets} packets)",
        name=original_name,
        packets=parsed["packet_count"],
    )
    return SuccessResponse(
        data={
            "id": capture_id,
            "filename": original_name,
            "size": len(content),
            "packets": parsed["packet_count"],
            "protocol_stats": parsed["protocol_stats"],
            "duration_seconds": parsed["duration_seconds"],
            "total_bytes": parsed["total_bytes"],
            "avg_packet_size": parsed["avg_packet_size"],
            "packets_per_second": parsed["packets_per_second"],
            "conversations": len(parsed["conversations"]),
        },
        message=f"Capture analyzed: {parsed['packet_count']} packets, {len(parsed['protocol_stats'])} protocols",
    )


async def _store_packets(db: AsyncSession, capture_id: uuid.UUID, packets: list[dict]) -> None:
    if not packets:
        return
    for i, p in enumerate(packets):
        db.add(
            Packet(
                capture_id=capture_id,
                seq=i,
                timestamp=_ts_to_dt(p.get("timestamp")),
                src_ip=p.get("src") or None,
                dst_ip=p.get("dst") or None,
                src_port=p.get("src_port"),
                dst_port=p.get("dst_port"),
                protocol=p.get("protocol") or "Other",
                length=p.get("length") or 0,
                info=(p.get("info") or "")[:500] or None,
            )
        )
        if i % 2000 == 1999:
            await db.flush()


async def _store_conversations(
    db: AsyncSession, capture_id: uuid.UUID, conversations: list[dict]
) -> None:
    if not conversations:
        return
    for c in conversations:
        db.add(
            Conversation(
                capture_id=capture_id,
                src_ip=c.get("src_ip") or None,
                dst_ip=c.get("dst_ip") or None,
                src_port=c.get("src_port"),
                dst_port=c.get("dst_port"),
                protocol=c.get("protocol") or "Other",
                packets=c.get("packets") or 0,
                bytes=c.get("bytes") or 0,
            )
        )


def _capture_active(info: Optional[dict]) -> bool:
    """True when a capture entry is still running, whether backed by an
    external capture tool process or a Scapy capture thread."""
    if not info:
        return False
    proc = info.get("process")
    if proc is not None and proc.returncode is None:
        return True
    state = info.get("state")
    thread = info.get("thread")
    if state is not None and thread is not None:
        return (not state.get("stop")) and thread.is_alive()
    return False


@router.get("/{capture_id}/status", response_model=SuccessResponse[dict])
async def get_capture_status(capture_id: str, db: AsyncSession = Depends(get_db)):
    """Live status for an active capture: current packet count, bytes and duration."""
    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        return SuccessResponse(data={}, message="Invalid capture ID format")

    result = await db.execute(select(PacketCapture).where(PacketCapture.id == uid))
    capture = result.scalar_one_or_none()
    if not capture:
        return SuccessResponse(data={}, message="Capture not found")

    info = ACTIVE_CAPTURES.get(capture_id)
    running = _capture_active(info)

    started_at = capture.capture_started_at or (info.get("started_at") if info else None)
    duration = 0.0
    if started_at:
        started = started_at if isinstance(started_at, datetime) else _parse_dt(str(started_at))
        if started:
            duration = max(0.0, (datetime.now(timezone.utc) - started).total_seconds())

    filepath = Path(capture.filepath)
    bytes_written = filepath.stat().st_size if filepath.exists() else 0
    if info and info.get("kind") == "scapy":
        packets = (info.get("state") or {}).get("count") or 0
    else:
        packets = _count_pcap_packets(filepath) if bytes_written > 0 else 0

    if running:
        return SuccessResponse(
            data={
                "status": "capturing",
                "packets": packets,
                "bytes": bytes_written,
                "duration_seconds": round(duration, 1),
                "started_at": started_at.isoformat() if isinstance(started_at, datetime) else None,
                "interface": info.get("interface") if info else None,
            },
            message="Capture is running",
        )
    return SuccessResponse(
        data={
            "status": "completed" if capture.capture_ended_at else "pending",
            "packets": capture.packet_count or 0,
            "bytes": capture.file_size or 0,
            "duration_seconds": capture.duration_seconds or 0.0,
            "started_at": capture.capture_started_at.isoformat() if capture.capture_started_at else None,
            "interface": None,
        },
        message="Capture is not active",
    )


@router.post("/start", response_model=SuccessResponse[dict])
async def start_capture(
    interface: str = Form("auto", description="Network interface to capture on ('auto' picks a sensible default)"),
    filter_expr: Optional[str] = Form(None, description="BPF filter expression"),
    assessment_id: Optional[str] = Form(None, description="Assessment UUID to associate"),
    db: AsyncSession = Depends(get_db),
):
    from app.core.config import settings

    # --- 1. Prevent multiple simultaneous captures ---
    for cid in list(ACTIVE_CAPTURES.keys()):
        info = ACTIVE_CAPTURES.get(cid)
        if _capture_active(info):
            return SuccessResponse(
                data={},
                message="Another live capture is already in progress - stop it before starting a new one",
            )
        ACTIVE_CAPTURES.pop(cid, None)

    # --- 2. Capture backend detection ---
    # Preferred: an external capture tool (dumpcap/tshark/tcpdump). When none is
    # installed, fall back to the Scapy backend, which writes a classic pcap
    # file that the existing parser and storage pipeline handle unchanged.
    tool, kind = _find_capture_tool()
    if not tool:
        if not _scapy_capture_available():
            return SuccessResponse(data={}, message=_no_capture_tool_message())
        backend = "scapy"
    else:
        backend = kind
        if not _npcap_installed():
            return SuccessResponse(
                data={},
                message="The Npcap driver is not installed - install Npcap (https://npcap.com) to enable live capture. Uploading a PCAP file still works.",
            )

    # --- 3. Resolve interface ---
    if interface in ("", "any", "auto"):
        if backend == "scapy":
            iface = _default_interface_scapy()
        else:
            iface = _default_interface(tool)
        if iface is None:
            return SuccessResponse(
                data={},
                message="No capture interfaces found. Make sure the Npcap driver is installed and running.",
            )
    else:
        iface = interface

    # --- 4. Destination file ---
    capture_id = str(uuid.uuid4())
    dest_dir = settings.BASE_DIR / ".." / "captures"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / f"live_{capture_id}.pcap"

    # --- 5/6. Spawn the capture backend ---
    state = None
    thread = None
    process = None
    if backend == "scapy":
        # Scapy backend: run the capture loop in a daemon thread. No subprocess
        # is involved; the worker writes packets to the pcap file incrementally.
        state = {"stop": False, "count": 0, "error": None, "filter_disabled": False}
        thread = threading.Thread(
            target=_scapy_capture_worker,
            args=(iface, dest_path, filter_expr, state),
            daemon=True,
            name=f"scapy-capture-{capture_id}",
        )
        thread.start()
        logger.info(
            "Live capture (scapy backend) started on interface {iface} (requested={requested}, selected={selected}, backend={backend}, dest={dest})",
            iface=iface,
            requested=interface,
            selected=iface,
            backend=backend,
            dest=dest_path,
        )
    else:
        # Tool-specific arguments
        if kind == "dumpcap":
            # -F pcap writes classic pcap (each record written incrementally, so a
            # hard kill still leaves a parseable file). Note: modern dumpcap emits
            # nanosecond-pcap magics; the parser accepts both micro/nano variants.
            args = ["-F", "pcap", "-i", iface, "-w", str(dest_path)]
            if filter_expr:
                args += ["-f", filter_expr]
        elif kind == "tshark":
            args = ["-i", iface, "-w", str(dest_path), "-F", "pcap"]
            if filter_expr:
                args += ["-f", filter_expr]
        else:  # tcpdump
            args = ["-i", iface, "-w", str(dest_path)]
            if filter_expr:
                args.append(filter_expr)

        # subprocess.Popen (not asyncio.create_subprocess_exec): with `--reload`,
        # uvicorn 0.52 runs on a SelectorEventLoop on Windows, where asyncio
        # subprocess support raises NotImplementedError. Popen via to_thread works
        # on any event loop and also allows CREATE_NO_WINDOW (no console popups).
        logger.info(
            "Live capture command: {cmd} (requested={requested}, selected={selected}, backend={backend}, dest={dest})",
            cmd=" ".join([tool] + args),
            requested=interface,
            selected=iface,
            backend=backend,
            dest=dest_path,
        )
        try:
            popen_kwargs = dict(stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if os.name == "nt":
                popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            process = await asyncio.to_thread(
                subprocess.Popen, [tool, *args], **popen_kwargs
            )
        except Exception as e:
            logger.error("Failed to spawn capture tool {tool}: {error}", tool=tool, error=str(e))
            return SuccessResponse(
                data={},
                message=f"Failed to start live capture: {e}",
            )

    # --- 7. Early failure detection (bad interface, permission errors, ...) ---
    await asyncio.sleep(2.5)
    if backend == "scapy":
        if state.get("error"):
            dest_path.unlink(missing_ok=True)
            logger.warning(
                "Scapy capture failed on interface {iface}: {error}",
                iface=iface,
                error=state["error"],
            )
            return SuccessResponse(
                data={},
                message=(
                    f"Live capture failed to start on interface '{iface}': {state['error']} "
                    "- check that the interface exists and that the backend can capture on it"
                ),
            )
    elif process.poll() is not None:
        error_text = ""
        if process.stderr:
            try:
                error_text = await asyncio.to_thread(
                    process.stderr.read, 65536
                )
                error_text = error_text.decode(errors="replace").strip()
            except Exception:
                pass
        dest_path.unlink(missing_ok=True)
        logger.warning(
            "Capture tool exited immediately (code {code}): {error}",
            code=process.returncode,
            error=error_text,
        )
        return SuccessResponse(
            data={},
            message=(
                f"Live capture failed to start on interface '{iface}' "
                f"(exit code {process.returncode}): {error_text or 'unknown error'} "
                "- check that the interface exists and that Npcap permits access"
            ),
        )

    # --- 8. Persist capture row and track the process ---
    scan_uuid = None
    if assessment_id:
        try:
            scan_uuid = uuid.UUID(assessment_id)
        except ValueError:
            scan_uuid = None

    capture = PacketCapture(
        id=uuid.UUID(capture_id),
        scan_id=scan_uuid,
        filename=f"live_{capture_id}.pcap",
        filepath=str(dest_path),
        file_size=0,
        packet_count=0,
        filter=filter_expr,
        capture_started_at=datetime.now(timezone.utc),
    )
    db.add(capture)
    await db.commit()

    ACTIVE_CAPTURES[capture_id] = {
        "process": process,
        "thread": thread,
        "state": state,
        "kind": backend,
        "started_at": capture.capture_started_at,
        "interface": iface,
        "tool": tool or "scapy",
    }
    logger.info(
        "Live capture started: {id} on interface {iface} with {tool}",
        id=capture_id,
        iface=iface,
        tool=tool or "scapy",
    )
    return SuccessResponse(
        data={
            "id": capture_id,
            "interface": iface,
            "filename": capture.filename,
            "tool": tool or "scapy",
        },
        message=f"Live capture started on '{iface}' ({tool or 'scapy'})",
    )


@router.post("/stop", response_model=SuccessResponse[dict])
async def stop_capture(
    capture_id: str = Form(..., description="Capture ID to stop"),
    db: AsyncSession = Depends(get_db),
):
    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        return SuccessResponse(data={}, message="Invalid capture ID format")

    result = await db.execute(select(PacketCapture).where(PacketCapture.id == uid))
    capture = result.scalar_one_or_none()
    if not capture:
        return SuccessResponse(data={}, message="Capture not found")

    # --- 1. Stop the capture cleanly ---
    info = ACTIVE_CAPTURES.pop(capture_id, None)
    process = info.get("process") if info else None
    state = info.get("state") if info else None
    thread = info.get("thread") if info else None
    stop_error = ""
    if process is not None and process.poll() is None:
        try:
            process.terminate()
            await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=8)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                await asyncio.to_thread(
                    subprocess.run,
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True,
                    timeout=15,
                )
                await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5)
            except Exception as e:
                stop_error = f" (force-kill failed: {e})"
        if process.stderr:
            try:
                tail = await asyncio.to_thread(process.stderr.read, 65536)
                stop_error += " " + tail.decode(errors="replace").strip()
            except Exception:
                pass
    elif thread is not None and thread.is_alive():
        # Scapy backend: signal the sniff loop and wait for it to finish and
        # close the pcap writer so the file is complete and parseable.
        state["stop"] = True
        try:
            await asyncio.wait_for(asyncio.to_thread(thread.join), timeout=8)
        except asyncio.TimeoutError:
            stop_error = " (Scapy capture thread did not exit cleanly)"

    # --- 2. Parse the captured file ---
    filepath = Path(capture.filepath)
    parsed = None
    parse_error = None
    if filepath.exists() and filepath.stat().st_size > 0:
        try:
            parsed = parse_capture_file(filepath.read_bytes())
        except PcapParseError as e:
            parse_error = str(e)
            logger.warning("Failed to parse stopped capture {id}: {error}", id=capture_id, error=str(e))
    elif not filepath.exists():
        parse_error = "capture file was not created"

    # --- 3. Update the capture record ---
    now = datetime.now(timezone.utc)
    capture.capture_ended_at = now
    if parsed:
        capture.packet_count = parsed["packet_count"]
        capture.duration_seconds = parsed["duration_seconds"]
        capture.total_bytes = parsed["total_bytes"]
        capture.avg_packet_size = parsed["avg_packet_size"]
        capture.packets_per_second = parsed["packets_per_second"]
        capture.protocol_stats = parsed["protocol_stats"]
        if parsed["capture_ended_at"]:
            capture.capture_ended_at = _parse_dt(parsed["capture_ended_at"])
    capture.file_size = filepath.stat().st_size if filepath.exists() else 0

    try:
        await db.flush()
        if parsed:
            await _store_packets(db, capture.id, parsed["packets"])
            await _store_conversations(db, capture.id, parsed["conversations"])
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.error("Failed to store stopped capture data: {error}", error=str(e))

    logger.info(
        "Live capture stopped: {id} ({packets} packets)",
        id=capture_id,
        packets=capture.packet_count or 0,
    )
    if parsed:
        message = f"Capture stopped with {capture.packet_count} packets captured and analyzed"
    else:
        message = f"Capture stopped but no packets could be parsed{': ' + parse_error if parse_error else ''}"
    return SuccessResponse(
        data={
            "id": capture_id,
            "packets": capture.packet_count or 0,
            "protocol_stats": capture.protocol_stats or {},
            "file_size": capture.file_size or 0,
            "warning": stop_error.strip() or None,
        },
        message=message,
    )


def _ts_to_dt(ts: Optional[float]) -> Optional[datetime]:
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _parse_dt(iso_str: Optional[str]) -> Optional[datetime]:
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _format_size(size: Optional[int]) -> str:
    if size is None:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} TB"
