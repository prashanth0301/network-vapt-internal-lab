import platform
import re
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from loguru import logger

from app.services.nmap_service import NmapHostResult

_WINDOWS = platform.system() == "Windows"

OUI_TABLE: dict[str, str] = {
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "PCS Systemtechnik (VirtualBox)",
    "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:1A:4A": "Dell",
    "00:0D:60": "Dell",
    "00:26:55": "Dell",
    "00:14:22": "Dell",
    "00:1B:21": "Intel",
    "00:1F:29": "Intel",
    "00:25:64": "Intel",
    "00:1E:4F": "Hewlett Packard",
    "00:17:A4": "Hewlett Packard",
    "3C:52:82": "Cisco",
    "00:0C:42": "Acer",
    "00:22:68": "Realtek",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:11:32": "Samsung",
    "00:1A:7D": "Netgear",
    "00:1F:33": "Netgear",
    "20:37:06": "Netgear",
    "00:23:69": "TP-Link",
    "50:C7:BF": "TP-Link",
    "CC:32:E5": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "70:4F:57": "TP-Link",
}


def _run_cmd(args: list[str], timeout: float = 2.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = (proc.stdout or b"").decode("utf-8", errors="replace")
        return proc.returncode, output
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug("Command failed {args}: {error}", args=args[:1], error=str(e))
        return 1, ""


def reverse_dns(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and "." in name and not name.endswith(".local"):
            return name
    except (socket.herror, socket.gaierror, OSError, TimeoutError):
        pass
    return None


def netbios_name(ip: str) -> Optional[str]:
    if _WINDOWS:
        code, out = _run_cmd(["nbtstat", "-A", ip], timeout=3.0)
        if code == 0:
            for line in out.splitlines():
                match = re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", line)
                if match:
                    return match.group(1).strip()
    else:
        code, out = _run_cmd(["nmblookup", "-A", ip], timeout=3.0)
        if code == 0:
            match = re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", out, re.MULTILINE)
            if match:
                return match.group(1).strip()
    return None


def _load_arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    if _WINDOWS:
        code, out = _run_cmd(["arp", "-a"], timeout=5.0)
        if code == 0:
            for line in out.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
                if match:
                    ip, mac = match.groups()
                    table[ip] = mac.replace("-", ":").lower()
    else:
        for cmd in (["ip", "neigh", "show"], ["arp", "-an"]):
            code, out = _run_cmd(cmd, timeout=5.0)
            if code == 0:
                for line in out.splitlines():
                    match = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-f]{2}(?::[0-9a-f]{2}){5})", line)
                    if match:
                        ip, mac = match.groups()
                        table[ip] = mac.lower()
                break
    return table


def oui_lookup(mac: str) -> Optional[str]:
    normalized = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
    if len(normalized) < 6:
        return None
    prefix = ":".join(normalized[i : i + 2] for i in range(0, 6, 2))
    if prefix not in OUI_TABLE:
        for oui, vendor in OUI_TABLE.items():
            if prefix.upper() == oui.upper():
                return vendor
    return OUI_TABLE.get(prefix)


def _ping_ttl(ip: str) -> Optional[int]:
    if _WINDOWS:
        code, out = _run_cmd(["ping", "-n", "1", "-w", "400", ip], timeout=3.0)
    else:
        code, out = _run_cmd(["ping", "-c", "1", "-W", "1", ip], timeout=3.0)
    if code != 0:
        return None
    match = re.search(r"[Tt][Tt][Ll]=(\d+)", out)
    if not match:
        return None
    return int(match.group(1))


def _os_from_ttl(ttl: int) -> tuple[Optional[str], Optional[int]]:
    if ttl in (127, 128, 129):
        return "Windows", 80
    if ttl == 255:
        return "Cisco IOS / Unix", 70
    if ttl == 64:
        return "Linux / Unix", 75
    if 60 <= ttl <= 63:
        return "Linux (hardened TTL)", 50
    if ttl == 32:
        return "Windows 9x / CE", 40
    return None, None


def _http_server_header(ip: str) -> Optional[str]:
    for port in (80, 443):
        try:
            with socket.create_connection((ip, port), timeout=1.5) as sock:
                if port == 443:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock, server_hostname=ip) as tls:
                        tls.settimeout(1.5)
                        tls.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                        data = tls.recv(2048)
                else:
                    sock.settimeout(1.5)
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
                    data = sock.recv(2048)
                text = data.decode("utf-8", errors="replace")
                match = re.search(r"(?im)^Server:\s*(.+)$", text)
                if match:
                    return match.group(1).strip()
        except (OSError, socket.timeout, ssl.SSLError):
            continue
    return None


def _os_from_http(header: str) -> tuple[Optional[str], Optional[int]]:
    header_lower = header.lower()
    if "iis" in header_lower:
        return "Windows Server", 75
    if "ubuntu" in header_lower:
        return "Ubuntu Linux", 60
    if "debian" in header_lower:
        return "Debian Linux", 60
    if "centos" in header_lower or "red hat" in header_lower:
        return "Red Hat Linux", 60
    if "apache" in header_lower or "nginx" in header_lower:
        return None, None
    return None, None


def _ssh_banner(ip: str) -> Optional[str]:
    try:
        with socket.create_connection((ip, 22), timeout=2.0) as sock:
            sock.settimeout(2.0)
            data = sock.recv(512)
        banner = data.decode("utf-8", errors="replace").strip()
        if banner.startswith("SSH-2.0"):
            return banner
    except (OSError, socket.timeout):
        pass
    return None


def _os_from_ssh(banner: str) -> tuple[Optional[str], Optional[int]]:
    banner_lower = banner.lower()
    if "windows" in banner_lower:
        return "Windows", 70
    if "ubuntu" in banner_lower:
        return "Ubuntu Linux", 55
    if "debian" in banner_lower:
        return "Debian Linux", 55
    if "centos" in banner_lower or "rhel" in banner_lower:
        return "Red Hat Linux", 55
    return None, None


def _enrich_one(
    host: NmapHostResult,
    arp_table: dict[str, str],
) -> NmapHostResult:
    ip = host.ip_address
    if not ip or host.status != "up":
        return host

    if not host.hostname:
        name = reverse_dns(ip)
        if name:
            host.hostname = name

    if not host.mac_address:
        mac = arp_table.get(ip)
        if mac:
            host.mac_address = mac

    if host.mac_address and not host.vendor:
        vendor = oui_lookup(host.mac_address)
        if vendor:
            host.vendor = vendor

    if host.hostname and not host.mac_address:
        nb = netbios_name(ip)
        if nb:
            host.hostname = nb

    if not host.os_name:
        hints: list[tuple[Optional[str], Optional[int]]] = []
        ttl = _ping_ttl(ip)
        if ttl is not None:
            hints.append(_os_from_ttl(ttl))
        server = _http_server_header(ip)
        if server:
            hints.append(_os_from_http(server))
        banner = _ssh_banner(ip)
        if banner:
            hints.append(_os_from_ssh(banner))
        best_name, best_conf = None, None
        for name, conf in hints:
            if name and (best_conf is None or (conf or 0) > best_conf):
                best_name, best_conf = name, conf
        if best_name:
            host.os_name = best_name
            host.os_accuracy = best_conf

    return host


def enrich_hosts(hosts: list[NmapHostResult]) -> list[NmapHostResult]:
    arp_table = _load_arp_table()
    if not hosts:
        return hosts
    workers = min(64, max(8, len(hosts)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        enriched = list(pool.map(lambda h: _enrich_one(h, arp_table), hosts))
    logger.info(
        "Host enrichment complete: {count} hosts processed, {macs} MAC addresses, {names} hostnames",
        count=len(enriched),
        macs=sum(1 for h in enriched if h.mac_address),
        names=sum(1 for h in enriched if h.hostname),
    )
    return enriched
