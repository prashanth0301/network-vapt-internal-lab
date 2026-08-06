import asyncio
import ipaddress
import os
import shutil
import socket
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import psutil
from loguru import logger


@dataclass
class NmapPortResult:
    port: int
    protocol: str = "tcp"
    state: str = "unknown"
    reason: Optional[str] = None
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    tunnel: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class NmapHostResult:
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    os_accuracy: Optional[int] = None
    status: str = "unknown"
    latency: Optional[float] = None
    open_ports: list[NmapPortResult] = field(default_factory=list)


@dataclass
class NmapScanResult:
    scan_type: str
    target: str
    hosts: list[NmapHostResult] = field(default_factory=list)
    raw_output: Optional[str] = None
    error: Optional[str] = None
    duration_seconds: Optional[float] = None
    completed_at: Optional[datetime] = None


SCAN_TYPES = {
    "ping_sweep": {
        "args": [
            "-sn",
            "-n",
            "-PE",
            "--max-retries", "0",
            "--max-rtt-timeout", "1000ms",
            "--min-parallelism", "100",
            "--host-timeout", "8s",
        ],
        "description": "ARP discovery on directly connected subnets, ICMP echo request otherwise",
    },
    "arp_scan": {
        "args": ["-sn", "-PR"],
        "description": "ARP request scan (local network only)",
    },
    "quick_scan": {
        "args": ["-sn", "-T4", "-n", "--reason", "--max-retries", "1"],
        "description": "Quick ping sweep with timing template T4",
    },
    "tcp_syn": {
        "args": ["-Pn", "-sS", "-T4", "--max-retries", "2"],
        "description": "TCP SYN stealth scan (no host discovery)",
    },
    "tcp_connect": {
        "args": ["-Pn", "-sT", "-T4", "--max-retries", "2"],
        "description": "TCP Connect scan (no raw sockets needed, no host discovery)",
    },
    "udp_scan": {
        "args": ["-sU", "-T4", "--max-retries", "2"],
        "description": "UDP port scan",
    },
    "version_detection": {
        "args": ["-Pn", "-sV", "--version-intensity", "5", "--max-retries", "2"],
        "description": "Service version detection (no host discovery)",
    },
    "os_detection": {
        "args": ["-O", "--osscan-guess"],
        "description": "Operating system detection",
    },
    "vuln_scan": {
        "args": ["-Pn", "-sV", "--version-intensity", "5", "--script", "vuln,vulners", "-T4", "--max-retries", "2"],
        "description": "Service version detection with NSE vulnerability scripts (no host discovery)",
    },
}

SCAN_PROFILES = {
    "top_ports": {
        "display_name": "Top 1000 Ports",
        "description": "Scan the top 1000 most common ports",
        "ports": None,
        "args": ["--top-ports", "1000"],
    },
    "custom_range": {
        "display_name": "Custom Port Range",
        "description": "Scan a user-specified port range",
        "ports": None,
        "args": None,
    },
    "all_ports": {
        "display_name": "All Ports (1-65535)",
        "description": "Full TCP/UDP port scan",
        "ports": "1-65535",
        "args": None,
    },
}


def _find_nmap() -> str:
    found = shutil.which("nmap")
    if found:
        return found

    candidates = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Tools\Nmap\nmap.exe",
        r"D:\Nmap\nmap.exe",
        r"E:\Nmap\nmap.exe",
        r"F:\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
    ]

    try:
        import winreg
        for key in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for subkey in (
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Insecure.Nmap",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Insecure.Nmap",
            ):
                try:
                    with winreg.OpenKey(key, subkey) as k:
                        install_dir = winreg.QueryValueEx(k, "InstallLocation")[0]
                        nmap_path = os.path.join(install_dir, "nmap.exe")
                        if os.path.exists(nmap_path):
                            return nmap_path
                except (OSError, FileNotFoundError):
                    pass
    except ImportError:
        pass

    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return "nmap"


def _get_local_networks() -> list[ipaddress.IPv4Network]:
    """Return the directly connected IPv4 subnets of this machine."""
    networks: list[ipaddress.IPv4Network] = []
    try:
        addrs = psutil.net_if_addrs()
    except Exception:
        return networks

    for ifname, ifaddrs in addrs.items():
        for addr in ifaddrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            netmask = addr.netmask
            if not ip or not netmask:
                continue
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
                networks.append(
                    ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                )
            except ValueError:
                continue
    return networks


def _is_local_target(
    target: str,
    local_networks: Optional[list[ipaddress.IPv4Network]] = None,
) -> bool:
    """True when the target belongs to a directly connected local subnet."""
    if local_networks is None:
        local_networks = _get_local_networks()
    if not local_networks:
        return False

    candidates: list[ipaddress.IPv4Address] = []
    try:
        stripped = target.strip()
        if "/" in stripped:
            candidates.append(ipaddress.ip_network(stripped, strict=False).network_address)
        elif "-" in stripped:
            candidates.append(ipaddress.ip_address(stripped.split("-")[0].strip()))
        else:
            try:
                candidates.append(ipaddress.ip_address(stripped))
            except ValueError:
                candidates.append(ipaddress.ip_address(socket.gethostbyname(stripped)))
    except (ValueError, OSError):
        return False

    return any(
        any(candidate in network for network in local_networks)
        for candidate in candidates
    )


def _ping_sweep_probe(target: str) -> str:
    """Pick the ping sweep probe: -PR for local subnets, -PE otherwise."""
    return "-PR" if _is_local_target(target) else "-PE"


def build_command(
    scan_type: str,
    target: str,
    ports: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
) -> list[str]:
    nmap_bin = _find_nmap()
    scan_config = SCAN_TYPES.get(scan_type)

    if scan_config:
        cmd = [nmap_bin] + scan_config["args"]
    else:
        cmd = [nmap_bin, "-sn"]

    if scan_type == "ping_sweep":
        probe = _ping_sweep_probe(target)
        try:
            cmd[cmd.index("-PE")] = probe
        except ValueError:
            cmd.append(probe)
        if probe == "-PE":
            cmd.extend(["-PS80,443"])

    if ports:
        cmd.extend(["-p", ports])

    if extra_args:
        cmd.extend(extra_args)

    cmd.extend(["-oX", "-", "--no-stylesheet", target])
    return cmd


def parse_nmap_output(xml_content: str) -> list[NmapHostResult]:
    hosts: list[NmapHostResult] = []

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        logger.error("Failed to parse Nmap XML: {error}", error=str(e))
        return hosts

    for host_elem in root.findall("host"):
        host = _parse_host(host_elem)
        if host:
            hosts.append(host)

    return hosts


def _extract_banner(port_elem: ET.Element, service_elem: ET.Element) -> Optional[str]:
    banner = None
    for script_elem in port_elem.findall("script"):
        if script_elem.get("id") == "banner":
            output = script_elem.get("output")
            if output:
                banner = output.strip()
            break
    if not banner:
        banner_elem = service_elem.find("banner")
        if banner_elem is not None and banner_elem.text:
            banner = banner_elem.text.strip()
    return banner or None


def _parse_host(host_elem: ET.Element) -> Optional[NmapHostResult]:
    status_elem = host_elem.find("status")
    if status_elem is None:
        return None

    state = status_elem.get("state", "unknown")

    address_elem = host_elem.find("address")
    if address_elem is None:
        return None

    ip_address = address_elem.get("addr", "")
    addr_type = address_elem.get("addrtype", "")

    mac_address = None
    vendor = None
    if addr_type == "mac":
        mac_address = ip_address
        vendor = address_elem.get("vendor", "")

        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip_address = addr.get("addr", "")
                break

    hostname = None
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        hostname_elem = hostnames_elem.find("hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name", "")

    os_name = None
    os_version = None
    os_accuracy = None
    os_elem = host_elem.find("os")
    if os_elem is not None:
        osmatch_elem = os_elem.find("osmatch")
        if osmatch_elem is not None:
            os_name = osmatch_elem.get("name", "")
            os_accuracy_str = osmatch_elem.get("accuracy", "0")
            os_accuracy = int(os_accuracy_str) if os_accuracy_str.isdigit() else None

    latency = None
    times_elem = host_elem.find("times")
    if times_elem is not None:
        srtt = times_elem.get("srtt", "")
        if srtt:
            try:
                latency = float(srtt) / 1000.0
            except (ValueError, TypeError):
                pass

    open_ports: list[NmapPortResult] = []
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for port_elem in ports_elem.findall("port"):
            port_state_elem = port_elem.find("state")
            if port_state_elem is not None:
                port_state = port_state_elem.get("state", "unknown")
                port_obj = NmapPortResult(
                    port=int(port_elem.get("portid", 0)),
                    protocol=port_elem.get("protocol", "tcp"),
                    state=port_state,
                    reason=port_state_elem.get("reason", None),
                )
                if port_state == "open":
                    service_elem = port_elem.find("service")
                    if service_elem is not None:
                        port_obj.service_name = service_elem.get("name", None)
                        port_obj.product = service_elem.get("product", None)
                        port_obj.version = service_elem.get("version", None)
                        port_obj.extra_info = service_elem.get("extrainfo", None)
                        port_obj.tunnel = service_elem.get("tunnel", None)
                        port_obj.banner = _extract_banner(port_elem, service_elem)
                open_ports.append(port_obj)

    return NmapHostResult(
        ip_address=ip_address,
        hostname=hostname,
        mac_address=mac_address,
        vendor=vendor,
        os_name=os_name,
        os_version=os_version,
        os_accuracy=os_accuracy,
        status=state,
        latency=latency,
        open_ports=open_ports,
    )


async def run_scan(
    scan_type: str,
    target: str,
    ports: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    timeout: int = 300,
) -> NmapScanResult:
    cmd = build_command(scan_type, target, ports, extra_args)

    logger.info(
        "Running Nmap scan: {scan_type} on {target}",
        scan_type=scan_type,
        target=target,
    )
    logger.debug("Nmap command: {cmd}", cmd=" ".join(cmd))

    start_time = datetime.now(timezone.utc)

    loop = asyncio.get_event_loop()

    def run_sync() -> NmapScanResult:
        import subprocess
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
            )
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            xml_output = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
            stderr_output = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            if proc.returncode != 0:
                return NmapScanResult(
                    scan_type=scan_type, target=target,
                    error=stderr_output or f"Nmap exited with code {proc.returncode}",
                    duration_seconds=duration,
                )
            hosts = parse_nmap_output(xml_output)
            return NmapScanResult(
                scan_type=scan_type, target=target,
                hosts=hosts, raw_output=xml_output,
                duration_seconds=duration, completed_at=datetime.now(timezone.utc),
            )
        except subprocess.TimeoutExpired:
            return NmapScanResult(
                scan_type=scan_type, target=target,
                error=f"Scan timed out after {timeout} seconds",
            )
        except FileNotFoundError:
            return NmapScanResult(
                scan_type=scan_type, target=target,
                error="Nmap executable not found. Install nmap or check PATH.",
            )
        except Exception as e:
            return NmapScanResult(
                scan_type=scan_type, target=target,
                error=f"Nmap execution error: {type(e).__name__}: {str(e)}",
            )

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.error(
                "Nmap scan timed out after {timeout}s: {target}",
                timeout=timeout,
                target=target,
            )
            return NmapScanResult(
                scan_type=scan_type,
                target=target,
                error=f"Scan timed out after {timeout} seconds",
            )

        xml_output = stdout.decode("utf-8", errors="replace") if stdout else ""
        stderr_output = stderr.decode("utf-8", errors="replace") if stderr else ""

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

        if process.returncode != 0:
            logger.error(
                "Nmap scan failed (exit code {code}): {error}",
                code=process.returncode,
                error=stderr_output,
            )
            return NmapScanResult(
                scan_type=scan_type,
                target=target,
                error=stderr_output or f"Nmap exited with code {process.returncode}",
                duration_seconds=duration,
            )

        hosts = parse_nmap_output(xml_output)

        logger.info(
            "Nmap scan completed: found {count} hosts in {duration:.1f}s",
            count=len(hosts),
            duration=duration,
        )

        return NmapScanResult(
            scan_type=scan_type,
            target=target,
            hosts=hosts,
            raw_output=xml_output,
            duration_seconds=duration,
            completed_at=datetime.now(timezone.utc),
        )

    except NotImplementedError:
        logger.warning(
            "asyncio subprocess not supported, falling back to synchronous subprocess",
        )
        return await loop.run_in_executor(None, run_sync)

    except FileNotFoundError:
        error_msg = "Nmap executable not found. Install nmap or check PATH."
        logger.error(error_msg)
        return NmapScanResult(
            scan_type=scan_type,
            target=target,
            error=error_msg,
        )

    except Exception as e:
        error_msg = f"Nmap execution error: {type(e).__name__}: {str(e)}"
        logger.error(error_msg)
        return NmapScanResult(
            scan_type=scan_type,
            target=target,
            error=error_msg,
        )


def get_scan_type_args(scan_type: str) -> list[str]:
    config = SCAN_TYPES.get(scan_type, {})
    return config.get("args", ["-sn"])


def get_supported_scan_types() -> dict:
    return {k: v["description"] for k, v in SCAN_TYPES.items()}
