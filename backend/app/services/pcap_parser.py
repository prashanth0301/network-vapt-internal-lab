"""Pure-Python PCAP / PCAPNG parser with zero external dependencies.

Parses classic libpcap files (little/big endian) and pcapng streams,
extracting per-packet records, per-protocol packet counters, source and
destination conversations, byte statistics, duration, and capture window.
"""

import struct
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from typing import Optional


PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE_NS = b"\xa1\xb2\x3c\x4d"
PCAP_MAGIC_LE_NS = b"\x4d\x3c\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

PCAPNG_BLOCK_SHB = 0x0A0D0D0A
PCAPNG_BLOCK_IDB = 0x00000001
PCAPNG_BLOCK_SPB = 0x00000003
PCAPNG_BLOCK_EPB = 0x00000006

PCAPNG_OPT_ENDOFOPT = 0
PCAPNG_OPT_IF_TSRESOL = 9

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_VLAN_QINQ = 0x88A8

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

PROTOCOL_ORDER = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "HTTPS", "Other"]

MAX_PACKET_RECORDS = 100_000

TCP_FLAG_BITS = (
    (0x02, "SYN"),
    (0x10, "ACK"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x01, "FIN"),
    (0x20, "URG"),
)

ICMP_TYPE_NAMES = {
    0: "Echo (ping) reply",
    3: "Destination unreachable",
    5: "Redirect",
    8: "Echo (ping) request",
    11: "Time exceeded",
}


class PcapParseError(Exception):
    """Raised when a file cannot be parsed as a capture."""


def _utc_from_seconds(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


def _tcp_flag_str(flags: int) -> str:
    parts = [name for bit, name in TCP_FLAG_BITS if flags & bit]
    return ",".join(parts) if parts else "."


def _classify_ethernet(payload: bytes) -> Optional[dict]:
    """Classify an Ethernet II frame and return a packet record dict."""
    if len(payload) < 14:
        return None
    eth_type = struct.unpack(">H", payload[12:14])[0]

    while eth_type in (ETHERTYPE_VLAN, ETHERTYPE_VLAN_QINQ):
        if len(payload) < 18:
            return None
        eth_type = struct.unpack(">H", payload[16:18])[0]
        payload = payload[4:]

    if eth_type == ETHERTYPE_ARP:
        return _classify_arp(payload[14:])
    if eth_type == ETHERTYPE_IPV4:
        return _classify_ipv4(payload[14:])
    if eth_type == ETHERTYPE_IPV6:
        return _classify_ipv6(payload[14:])
    return {"protocol": "Other", "src": "", "dst": "", "src_port": None, "dst_port": None, "info": ""}


def _classify_ipv4(ip: bytes) -> Optional[dict]:
    if len(ip) < 9:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 4:
        return None
    protocol = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])

    if protocol == IP_PROTO_TCP:
        return _classify_transport(ip, ihl, src, dst, "TCP")
    if protocol == IP_PROTO_UDP:
        return _classify_transport(ip, ihl, src, dst, "UDP")
    if protocol == IP_PROTO_ICMP:
        return _classify_icmp(ip, ihl, src, dst)
    return {"protocol": "Other", "src": src, "dst": dst, "src_port": None, "dst_port": None, "info": ""}


def _classify_ipv6(ip: bytes) -> Optional[dict]:
    if len(ip) < 8:
        return None
    protocol = ip[6]
    src = _ipv6_str(ip[8:24])
    dst = _ipv6_str(ip[24:40])

    if protocol == IP_PROTO_TCP:
        return _classify_transport(ip, 40, src, dst, "TCP")
    if protocol == IP_PROTO_UDP:
        return _classify_transport(ip, 40, src, dst, "UDP")
    if protocol == IP_PROTO_ICMP:
        return _classify_icmp(ip, 40, src, dst)
    return {"protocol": "Other", "src": src, "dst": dst, "src_port": None, "dst_port": None, "info": ""}


def _ipv6_str(raw: bytes) -> str:
    words = struct.unpack(">8H", raw)
    return ":".join(f"{w:x}" for w in words)


def _classify_transport(ip: bytes, offset: int, src: str, dst: str, base: str) -> dict:
    if len(ip) < offset + 4:
        return {"protocol": base, "src": src, "dst": dst, "src_port": None, "dst_port": None, "info": ""}
    sport, dport = struct.unpack(">HH", ip[offset : offset + 4])

    protocol = base
    if base == "UDP" and (sport == 53 or dport == 53):
        protocol = "DNS"
    elif base == "TCP" and dport == 443:
        protocol = "HTTPS"
    elif base == "TCP" and (sport in (80, 8080) or dport in (80, 8080)):
        protocol = "HTTP"

    if base == "TCP":
        flags = 0
        if len(ip) >= offset + 14:
            flags = ip[offset + 13]
        info = f"{sport} \u2192 {dport} [{_tcp_flag_str(flags)}]"
    elif base == "UDP":
        udp_len = 0
        if len(ip) >= offset + 6:
            udp_len = struct.unpack(">H", ip[offset + 4 : offset + 6])[0]
        info = f"{sport} \u2192 {dport} Len={max(udp_len - 8, 0)}"
    else:
        info = f"{sport} \u2192 {dport}"

    return {
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "src_port": sport,
        "dst_port": dport,
        "info": info,
    }


def _classify_icmp(ip: bytes, offset: int, src: str, dst: str) -> dict:
    icmp_type = ip[offset] if len(ip) > offset else None
    name = ICMP_TYPE_NAMES.get(icmp_type, f"Type {icmp_type}" if icmp_type is not None else "ICMP")
    return {
        "protocol": "ICMP",
        "src": src,
        "dst": dst,
        "src_port": None,
        "dst_port": None,
        "info": name,
    }


def _classify_arp(arp: bytes) -> Optional[dict]:
    if len(arp) < 20:
        return None
    opcode = struct.unpack(">H", arp[6:8])[0]
    spa = ".".join(str(b) for b in arp[14:18])
    tpa = ".".join(str(b) for b in arp[24:28])
    sha = ":".join(f"{b:02x}" for b in arp[8:14])
    if opcode == 1:
        info = f"who-has {tpa} tell {spa}"
    elif opcode == 2:
        info = f"{spa} is-at {sha}"
    else:
        info = f"opcode {opcode}"
    return {
        "protocol": "ARP",
        "src": spa,
        "dst": tpa,
        "src_port": None,
        "dst_port": None,
        "info": info,
    }


def _classify_null(payload: bytes) -> Optional[dict]:
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
    return None


def _classify_raw(payload: bytes) -> Optional[dict]:
    if len(payload) < 1:
        return None
    version = payload[0] >> 4
    if version == 4:
        return _classify_ipv4(payload)
    if version == 6:
        return _classify_ipv6(payload)
    return None


def _classify_packet(payload: bytes, linktype: int) -> Optional[dict]:
    try:
        if linktype == LINKTYPE_ETHERNET:
            return _classify_ethernet(payload)
        if linktype == LINKTYPE_NULL:
            return _classify_null(payload)
        if linktype == LINKTYPE_RAW:
            return _classify_raw(payload)
        return None
    except Exception:
        return None


def _record_to_dict(record: dict, ts: Optional[float], length: int) -> dict:
    return {
        "timestamp": ts,
        "src": record.get("src", ""),
        "dst": record.get("dst", ""),
        "src_port": record.get("src_port"),
        "dst_port": record.get("dst_port"),
        "protocol": record.get("protocol", "Other"),
        "length": length,
        "info": record.get("info", ""),
    }


def _append_packet(
    packets: list,
    counter: Counter,
    conversations: dict,
    frame: bytes,
    linktype: int,
    ts: Optional[float],
) -> str:
    """Classify one frame, update stats, and append its record.

    Returns the classified protocol string (always a value).
    """
    length = len(frame)
    counter_total_packets = 0
    record = _classify_packet(frame, linktype)
    protocol = record["protocol"] if record else "Other"
    counter[protocol] += 1

    if len(packets) < MAX_PACKET_RECORDS:
        if record:
            packets.append(_record_to_dict(record, ts, length))
        else:
            packets.append(
                {"timestamp": ts, "src": "", "dst": "", "src_port": None, "dst_port": None, "protocol": "Other", "length": length, "info": ""}
            )

    if record:
        key = (record.get("src", ""), record.get("dst", ""), protocol)
        conv = conversations.get(key)
        if conv is None:
            conversations[key] = {
                "src_ip": record.get("src", ""),
                "dst_ip": record.get("dst", ""),
                "src_port": record.get("src_port"),
                "dst_port": record.get("dst_port"),
                "protocol": protocol,
                "packets": 1,
                "bytes": length,
            }
        else:
            conv["packets"] += 1
            conv["bytes"] += length
            if conv["src_port"] is None and record.get("src_port") is not None:
                conv["src_port"] = record["src_port"]
            if conv["dst_port"] is None and record.get("dst_port") is not None:
                conv["dst_port"] = record["dst_port"]

    return protocol


def _build_summary(
    counter: Counter,
    total_packets: int,
    total_bytes: int,
    first_ts: Optional[float],
    last_ts: Optional[float],
    packets: list,
    conversations: dict,
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

    conversations_list = sorted(
        conversations.values(), key=lambda c: (c["packets"], c["bytes"]), reverse=True
    )

    return {
        "packet_count": total_packets,
        "protocol_stats": dict(ordered),
        "duration_seconds": round(max(duration, 0.0), 3),
        "capture_started_at": start.isoformat() if start else None,
        "capture_ended_at": end.isoformat() if end else None,
        "total_bytes": total_bytes,
        "avg_packet_size": round(total_bytes / total_packets, 1) if total_packets else 0.0,
        "packets_per_second": round(total_packets / duration, 2) if duration > 0 else 0.0,
        "packets": packets,
        "conversations": conversations_list,
    }


def _parse_pcap(data: bytes) -> dict:
    if len(data) < 24:
        raise PcapParseError("File too small to be a PCAP capture")

    magic = data[:4]
    if magic == PCAP_MAGIC_LE:
        byte_order = "<"
        ts_divisor = 1_000_000.0
    elif magic == PCAP_MAGIC_BE:
        byte_order = ">"
        ts_divisor = 1_000_000.0
    elif magic == PCAP_MAGIC_LE_NS:
        byte_order = "<"
        ts_divisor = 1_000_000_000.0
    elif magic == PCAP_MAGIC_BE_NS:
        byte_order = ">"
        ts_divisor = 1_000_000_000.0
    else:
        raise PcapParseError("Invalid PCAP magic bytes")

    version_major, version_minor = struct.unpack(
        byte_order + "HH", data[4:8]
    )
    if version_major not in (2, 3):
        raise PcapParseError(f"Unsupported PCAP version {version_major}.{version_minor}")

    linktype = struct.unpack(byte_order + "I", data[20:24])[0] & 0xFFFF

    counter: Counter[str] = Counter()
    conversations: dict = {}
    packets: list = []
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    total_packets = 0
    total_bytes = 0

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

        ts = ts_sec + (ts_usec / ts_divisor)
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        total_packets += 1
        total_bytes += incl_len

        _append_packet(packets, counter, conversations, frame, linktype, ts)

    return _build_summary(
        counter, total_packets, total_bytes, first_ts, last_ts, packets, conversations
    )


def _parse_pcapng(data: bytes) -> dict:
    if len(data) < 12:
        raise PcapParseError("File too small to be a PCAPNG capture")

    counter: Counter[str] = Counter()
    conversations: dict = {}
    packets: list = []
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    total_packets = 0
    total_bytes = 0
    linktypes: dict[int, int] = {}
    ts_resolution = 1_000_000
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
        elif block_type == PCAPNG_BLOCK_IDB:
            if len(body) >= 8:
                iface_id = len(linktypes)
                linktype = struct.unpack(byte_order + "H", body[0:2])[0]
                linktypes[iface_id] = linktype
                opt = 8
                while opt + 4 <= len(body):
                    code, olen = struct.unpack(byte_order + "HH", body[opt : opt + 4])
                    if code == PCAPNG_OPT_ENDOFOPT:
                        break
                    if code == PCAPNG_OPT_IF_TSRESOL and olen >= 1 and opt + 4 < len(body):
                        tsresol_byte = body[opt + 4]
                        if tsresol_byte & 0x80:
                            ts_resolution = 2 ** (tsresol_byte & 0x7F)
                        else:
                            ts_resolution = 10 ** (tsresol_byte & 0x7F)
                    opt += 4 + ((olen + 3) & ~3)
        elif block_type == PCAPNG_BLOCK_EPB:
            if len(body) >= 20:
                iface_id = struct.unpack(byte_order + "I", body[0:4])[0]
                ts_high = struct.unpack(byte_order + "I", body[4:8])[0]
                ts_low = struct.unpack(byte_order + "I", body[8:12])[0]
                caplen = struct.unpack(byte_order + "I", body[12:16])[0]
                if 20 + caplen <= len(body):
                    frame = body[20 : 20 + caplen]
                    ts_units = (ts_high << 32) | ts_low
                    ts = ts_units / ts_resolution
                    if first_ts is None:
                        first_ts = ts
                    last_ts = ts
                    total_packets += 1
                    total_bytes += caplen
                    _append_packet(
                        packets, counter, conversations, frame,
                        linktypes.get(iface_id, LINKTYPE_ETHERNET), ts,
                    )
        elif block_type == PCAPNG_BLOCK_SPB:
            if len(body) >= 4:
                iface_id = struct.unpack(byte_order + "I", body[0:4])[0]
                frame = body[4:]
                ts = last_ts if last_ts is not None else (first_ts if first_ts is not None else 0.0)
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
                total_packets += 1
                total_bytes += len(frame)
                _append_packet(
                    packets, counter, conversations, frame,
                    linktypes.get(iface_id, LINKTYPE_ETHERNET), ts,
                )

        offset += block_len

    if total_packets == 0:
        raise PcapParseError("No packets found in PCAPNG file")

    return _build_summary(
        counter, total_packets, total_bytes, first_ts, last_ts, packets, conversations
    )


def parse_capture_file(data: bytes) -> dict:
    """Parse raw capture file bytes and return packet statistics.

    Raises PcapParseError for unsupported/invalid input.
    """
    if not data:
        raise PcapParseError("Empty capture file")

    if data[:4] in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_LE_NS, PCAP_MAGIC_BE_NS):
        return _parse_pcap(data)
    if data[:4] == PCAPNG_MAGIC:
        return _parse_pcapng(data)
    raise PcapParseError(
        "Unsupported file format - expected .pcap or .pcapng capture"
    )
