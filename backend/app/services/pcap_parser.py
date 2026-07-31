"""Pure-Python PCAP / PCAPNG parser with zero external dependencies.

Parses classic libpcap files (little/big endian) and pcapng streams,
extracting per-protocol packet counters, duration, and capture window.
"""

import struct
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from typing import Optional


PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

PCAPNG_BLOCK_SHB = 0x0A0D0D0A
PCAPNG_BLOCK_IDB = 0x00000001
PCAPNG_BLOCK_EPB = 0x00000006
PCAPNG_BLOCK_SPB = 0x00000003

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_VLAN_QINQ = 0x88A8

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ICMP = 1

PROTOCOL_ORDER = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "Other"]


class PcapParseError(Exception):
    """Raised when a file cannot be parsed as a capture."""


def _utc_from_seconds(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _classify_ethernet(payload: bytes) -> Optional[str]:
    """Classify an Ethernet II frame by EtherType and transport ports."""
    if len(payload) < 14:
        return None
    eth_type = struct.unpack(">H", payload[12:14])[0]

    while eth_type in (ETHERTYPE_VLAN, ETHERTYPE_VLAN_QINQ):
        if len(payload) < 18:
            return None
        eth_type = struct.unpack(">H", payload[16:18])[0]
        payload = payload[4:]

    if eth_type == ETHERTYPE_ARP:
        return "ARP"
    if eth_type == ETHERTYPE_IPV4:
        return _classify_ipv4(payload[14:])
    if eth_type == ETHERTYPE_IPV6:
        return _classify_ipv6(payload[14:])
    return "Other"


def _classify_ipv4(ip: bytes) -> Optional[str]:
    if len(ip) < 9:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 4:
        return None
    protocol = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])

    if protocol == IP_PROTO_TCP:
        if len(ip) < ihl + 4:
            return "TCP"
        sport, dport = struct.unpack(">HH", ip[ihl : ihl + 4])
        return _classify_transport("TCP", sport, dport, src, dst)
    if protocol == IP_PROTO_UDP:
        if len(ip) < ihl + 4:
            return "UDP"
        sport, dport = struct.unpack(">HH", ip[ihl : ihl + 4])
        return _classify_transport("UDP", sport, dport, src, dst)
    if protocol == IP_PROTO_ICMP:
        return "ICMP"
    return "Other"


def _classify_ipv6(ip: bytes) -> Optional[str]:
    if len(ip) < 8:
        return None
    protocol = ip[6]
    src = _ipv6_str(ip[8:24])
    dst = _ipv6_str(ip[24:40])

    if protocol == IP_PROTO_TCP:
        if len(ip) < 44:
            return "TCP"
        sport, dport = struct.unpack(">HH", ip[40:44])
        return _classify_transport("TCP", sport, dport, src, dst)
    if protocol == IP_PROTO_UDP:
        if len(ip) < 44:
            return "UDP"
        sport, dport = struct.unpack(">HH", ip[40:44])
        return _classify_transport("UDP", sport, dport, src, dst)
    if protocol == IP_PROTO_ICMP:
        return "ICMP"
    return "Other"


def _ipv6_str(raw: bytes) -> str:
    words = struct.unpack(">8H", raw)
    return ":".join(f"{w:x}" for w in words)


def _classify_transport(
    base: str, sport: int, dport: int, src: str, dst: str
) -> str:
    if base == "UDP" and (sport == 53 or dport == 53):
        return "DNS"
    if base == "TCP" and sport == 443 or (base == "TCP" and dport == 443):
        return "HTTPS"
    if base == "TCP" and (sport in (80, 8080) or dport in (80, 8080)):
        return "HTTP"
    return base


def _classify_null(payload: bytes) -> Optional[str]:
    """BSD loopback header: 4-byte address family + IP packet."""
    if len(payload) < 4:
        return None
    family = struct.unpack("<I", payload[:4])[0]
    if family in (2, 24, 28, 30):
        ip = payload[4:]
        version = ip[0] >> 4 if len(ip) > 0 else 4
        if version == 4:
            return _classify_ipv4(ip)
        if version == 6:
            return _classify_ipv6(ip)
    return "Other"


def _classify_raw(payload: bytes) -> Optional[str]:
    if len(payload) < 1:
        return None
    version = payload[0] >> 4
    if version == 4:
        return _classify_ipv4(payload)
    if version == 6:
        return _classify_ipv6(payload)
    return "Other"


def _classify_packet(payload: bytes, linktype: int) -> Optional[str]:
    try:
        if linktype == LINKTYPE_ETHERNET:
            return _classify_ethernet(payload)
        if linktype == LINKTYPE_NULL:
            return _classify_null(payload)
        if linktype == LINKTYPE_RAW:
            return _classify_raw(payload)
        return "Other"
    except Exception:
        return "Other"


def _parse_pcap(data: bytes) -> dict:
    if len(data) < 24:
        raise PcapParseError("File too small to be a PCAP capture")

    magic = data[:4]
    if magic == PCAP_MAGIC_LE:
        byte_order = "<"
    elif magic == PCAP_MAGIC_BE:
        byte_order = ">"
    else:
        raise PcapParseError("Invalid PCAP magic bytes")

    version_major, version_minor = struct.unpack(
        byte_order + "HH", data[4:8]
    )
    if version_major not in (2, 3):
        raise PcapParseError(f"Unsupported PCAP version {version_major}.{version_minor}")

    linktype = struct.unpack(byte_order + "I", data[20:24])[0] & 0xFFFF

    counter: Counter[str] = Counter()
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    total_packets = 0

    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            byte_order + "IIII", data[offset : offset + 16]
        )
        offset += 16
        if incl_len > 65535 or offset + incl_len > len(data):
            break
        frame = data[offset : offset + incl_len]
        offset += incl_len

        ts = ts_sec + (ts_usec / 1_000_000.0)
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        total_packets += 1

        proto = _classify_packet(frame, linktype)
        if proto:
            counter[proto] += 1
        else:
            counter["Other"] += 1

    return _build_summary(counter, total_packets, first_ts, last_ts)


def _parse_pcapng(data: bytes) -> dict:
    if len(data) < 12:
        raise PcapParseError("File too small to be a PCAPNG capture")

    counter: Counter[str] = Counter()
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    total_packets = 0
    linktypes: dict[int, int] = {}
    ts_resolution = 1_000_000
    ts_offset = 0
    byte_order = "<"

    offset = 0
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack("<II", data[offset : offset + 8])
        if block_len < 12 or offset + block_len > len(data):
            break
        body = data[offset + 8 : offset + block_len - 4]

        if block_type == PCAPNG_BLOCK_SHB:
            if len(body) >= 12:
                byte_order = ">" if body[:4] == b"\x1a\x2b\x3c\x4d" else "<"
                ts_resolution = 1_000_000
                ts_offset = 0
        elif block_type == PCAPNG_BLOCK_IDB:
            if len(body) >= 8:
                iface_id = struct.unpack(byte_order + "H", body[0:2])[0]
                linktype = struct.unpack(byte_order + "H", body[2:4])[0]
                linktypes[iface_id] = linktype
                tsresol_byte = body[7]
                if tsresol_byte & 0x80:
                    ts_resolution = 2 ** (tsresol_byte & 0x7F)
                else:
                    ts_resolution = 10 ** (tsresol_byte & 0x7F)
        elif block_type == PCAPNG_BLOCK_EPB:
            if len(body) >= 20:
                iface_id = struct.unpack(byte_order + "I", body[0:4])[0]
                ts_high = struct.unpack(byte_order + "I", body[4:8])[0]
                ts_low = struct.unpack(byte_order + "I", body[8:12])[0]
                caplen = struct.unpack(byte_order + "I", body[12:16])[0]
                if 20 + caplen <= len(body):
                    frame = body[20 : 20 + caplen]
                    ts_units = (ts_high << 32) | ts_low
                    ts = (ts_units / ts_resolution) - ts_offset
                    if first_ts is None:
                        first_ts = ts
                    last_ts = ts
                    total_packets += 1
                    proto = _classify_packet(frame, linktypes.get(iface_id, LINKTYPE_ETHERNET))
                    counter[proto or "Other"] += 1

        offset += block_len

    if total_packets == 0:
        raise PcapParseError("No packets found in PCAPNG file")

    return _build_summary(counter, total_packets, first_ts, last_ts)


def _build_summary(
    counter: Counter,
    total_packets: int,
    first_ts: Optional[float],
    last_ts: Optional[float],
) -> dict:
    ordered: "OrderedDict[str, int]" = OrderedDict()
    for proto in PROTOCOL_ORDER:
        if counter.get(proto):
            ordered[proto] = counter[proto]
    for proto, count in counter.most_common():
        if proto not in ordered:
            ordered[proto] = count

    start = _utc_from_seconds(first_ts) if first_ts is not None else None
    end = _utc_from_seconds(last_ts) if last_ts is not None else None
    duration = (last_ts - first_ts) if first_ts is not None and last_ts is not None else 0.0

    return {
        "packet_count": total_packets,
        "protocol_stats": dict(ordered),
        "duration_seconds": round(max(duration, 0.0), 3),
        "capture_started_at": start.isoformat() if start else None,
        "capture_ended_at": end.isoformat() if end else None,
    }


def parse_capture_file(data: bytes) -> dict:
    """Parse raw capture file bytes and return packet statistics.

    Raises PcapParseError for unsupported/invalid input.
    """
    if not data:
        raise PcapParseError("Empty capture file")

    if data[:4] in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
        return _parse_pcap(data)
    if data[:4] == PCAPNG_MAGIC:
        return _parse_pcapng(data)
    raise PcapParseError(
        "Unsupported file format - expected .pcap or .pcapng capture"
    )
