"""Unit tests for the pure-Python PCAP / PCAPNG parser."""

import struct

import pytest

from app.services.pcap_parser import (
    PcapParseError,
    parse_capture_file,
)


def _ether(dst_mac: bytes, src_mac: bytes, eth_type: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", eth_type) + payload


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    src_b = bytes(int(o) for o in src.split("."))
    dst_b = bytes(int(o) for o in dst.split("."))
    total_len = 20 + len(payload)
    return (
        b"\x45\x00"
        + struct.pack(">H", total_len)
        + b"\x00\x01\x00\x00"
        + b"\x40"
        + bytes([proto])
        + b"\x00\x00"
        + src_b
        + dst_b
        + payload
    )


def _tcp(sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    header = (
        struct.pack(">HHII", sport, dport, 1000, 2000)
        + bytes([0x50 | (flags >> 8), flags & 0xFF])
        + struct.pack(">HHH", 65535, 0, 0)
    )
    return header + payload


def _udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack(">HHHH", sport, dport, length, 0) + payload


def _icmp(icmp_type: int, code: int = 0) -> bytes:
    return bytes([icmp_type, code]) + b"\x00\x00" + b"\x00\x00\x00\x01"


def _arp(op: int, spa: str, tpa: str, sha: bytes) -> bytes:
    spa_b = bytes(int(o) for o in spa.split("."))
    tpa_b = bytes(int(o) for o in tpa.split("."))
    return (
        struct.pack(">HH", 1, 0x0800)
        + bytes([6, 4])
        + struct.pack(">H", op)
        + sha
        + spa_b
        + b"\x00" * 6
        + tpa_b
    )


def _frame(record: dict) -> bytes:
    frame = _ether(
        bytes.fromhex("001122334455"),
        bytes.fromhex("aabbccddeeff"),
        record["eth_type"],
        record["payload"],
    )
    return frame


def _pcap_le(packet_records: list[tuple[float, bytes]]) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out = bytearray(header)
    for ts, frame in packet_records:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame))
        out += frame
    return bytes(out)


def _pcap_be(packet_records: list[tuple[float, bytes]]) -> bytes:
    header = struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    out = bytearray(header)
    for ts, frame in packet_records:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        out += struct.pack(">IIII", sec, usec, len(frame), len(frame))
        out += frame
    return bytes(out)


def _pcapng_block(block_type: int, body: bytes, byte_order: str = "<") -> bytes:
    padded = body + b"\x00" * ((-len(body)) % 4)
    block_len = 12 + len(padded)
    out = struct.pack("<II", block_type, block_len)
    out += padded
    out += struct.pack(byte_order + "I", block_len)
    return out


def _pcapng(packet_records: list[tuple[float, bytes]]) -> bytes:
    shb = _pcapng_block(
        0x0A0D0D0A,
        b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHII", 1, 0, 0, 0)
        + struct.pack("<HH", 0, 0),
    )
    idb_body = (
        struct.pack("<HHI", 1, 0, 65535)  # linktype=1, reserved, snaplen
        + struct.pack("<HHB", 9, 1, 6)  # if_tsresol option: 10^-6
        + b"\x00" * 3  # pad option
        + struct.pack("<HH", 0, 0)  # end of options
    )
    idb = _pcapng_block(0x00000001, idb_body)
    out = bytearray(shb + idb)
    for ts, frame in packet_records:
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        epb = _pcapng_block(
            0x00000006,
            struct.pack("<IIIII", 0, sec, usec, len(frame), len(frame)) + frame,
        )
        out += epb
    return bytes(out)


TCP_SYN = _frame(
    {"eth_type": 0x0800, "payload": _ipv4("10.0.0.1", "10.0.0.2", 6, _tcp(40000, 80, 0x02))}
)
TCP_ACK = _frame(
    {"eth_type": 0x0800, "payload": _ipv4("10.0.0.2", "10.0.0.1", 6, _tcp(80, 40000, 0x10))}
)
DNS_Q = _frame(
    {"eth_type": 0x0800, "payload": _ipv4("10.0.0.1", "8.8.8.8", 17, _udp(53000, 53, b"\x12\x34\x01\x00"))}
)
ICMP_PING = _frame(
    {"eth_type": 0x0800, "payload": _ipv4("10.0.0.1", "10.0.0.2", 1, _icmp(8))}
)
ICMP_REPLY = _frame(
    {"eth_type": 0x0800, "payload": _ipv4("10.0.0.2", "10.0.0.1", 1, _icmp(0))}
)
ARP_REQ = _frame(
    {"eth_type": 0x0806, "payload": _arp(1, "10.0.0.1", "10.0.0.2", bytes.fromhex("001122334455"))}
)
HTTPS_SYN = _frame(
    {"eth_type": 0x0800, "payload": _ipv4("10.0.0.1", "10.0.0.3", 6, _tcp(45000, 443, 0x02))}
)


class TestParseClassicPcap:
    def test_little_endian_pcap(self):
        records = [
            (1000.0, TCP_SYN),
            (1000.5, TCP_ACK),
            (1001.0, DNS_Q),
            (1001.5, ICMP_PING),
            (1002.0, ARP_REQ),
            (1002.5, HTTPS_SYN),
        ]
        data = _pcap_le(records)
        result = parse_capture_file(data)

        assert result["packet_count"] == 6
        assert result["total_bytes"] == sum(len(r[1]) for r in records)
        assert "TCP" not in result["protocol_stats"]
        assert result["protocol_stats"]["HTTP"] == 2
        assert result["protocol_stats"]["HTTPS"] == 1
        assert result["protocol_stats"]["DNS"] == 1
        assert result["protocol_stats"]["ICMP"] == 1
        assert result["protocol_stats"]["ARP"] == 1
        assert sum(result["protocol_stats"].values()) == 6
        assert result["duration_seconds"] == 2.5
        assert result["capture_started_at"] is not None
        assert result["capture_ended_at"] is not None

    def test_big_endian_pcap(self):
        records = [(1000.0, TCP_SYN), (1001.0, DNS_Q)]
        data = _pcap_be(records)
        result = parse_capture_file(data)
        assert result["packet_count"] == 2
        assert result["protocol_stats"]["HTTP"] == 1
        assert result["protocol_stats"]["DNS"] == 1

    def test_packet_records_match_count(self):
        records = [(1000.0, TCP_SYN), (1000.5, TCP_ACK), (1001.0, DNS_Q)]
        result = parse_capture_file(_pcap_le(records))
        assert len(result["packets"]) == 3
        assert result["packets"][0]["protocol"] == "HTTP"
        assert result["packets"][0]["src"] == "10.0.0.1"
        assert result["packets"][0]["dst"] == "10.0.0.2"
        assert result["packets"][0]["src_port"] == 40000
        assert result["packets"][0]["dst_port"] == 80
        assert "[SYN]" in result["packets"][0]["info"]
        assert result["packets"][1]["protocol"] == "HTTP"
        assert result["packets"][2]["protocol"] == "DNS"

    def test_conversations_aggregate(self):
        records = [
            (1000.0, TCP_SYN),
            (1000.5, TCP_ACK),
            (1001.0, DNS_Q),
            (1001.5, HTTPS_SYN),
        ]
        result = parse_capture_file(_pcap_le(records))
        convs = result["conversations"]
        by_key = {(c["src_ip"], c["dst_ip"], c["protocol"]): c for c in convs}

        http_conv = by_key[("10.0.0.1", "10.0.0.2", "HTTP")]
        assert http_conv["packets"] == 1

        http_conv_rev = by_key[("10.0.0.2", "10.0.0.1", "HTTP")]
        assert http_conv_rev["packets"] == 1

        dns_conv = by_key[("10.0.0.1", "8.8.8.8", "DNS")]
        assert dns_conv["packets"] == 1
        assert dns_conv["dst_port"] == 53

        total_conv_packets = sum(c["packets"] for c in convs)
        assert total_conv_packets == 4

    def test_same_pair_aggregates(self):
        records = [(1000.0, TCP_SYN), (1000.5, TCP_ACK), (1001.0, TCP_SYN)]
        result = parse_capture_file(_pcap_le(records))
        by_key = {(c["src_ip"], c["dst_ip"], c["protocol"]): c for c in result["conversations"]}
        conv = by_key[("10.0.0.1", "10.0.0.2", "HTTP")]
        assert conv["packets"] == 2
        assert conv["bytes"] == len(TCP_SYN) * 2

    def test_avg_and_pps(self):
        records = [(1000.0, TCP_SYN), (1002.0, DNS_Q)]
        result = parse_capture_file(_pcap_le(records))
        avg = round(result["total_bytes"] / 2, 1)
        assert result["avg_packet_size"] == avg
        assert result["packets_per_second"] == round(2 / 2.0, 2)

    def test_packet_record_cap(self, monkeypatch):
        import app.services.pcap_parser as parser_mod

        monkeypatch.setattr(parser_mod, "MAX_PACKET_RECORDS", 5)
        records = [(1000.0 + i * 0.1, TCP_SYN) for i in range(8)]
        result = parse_capture_file(_pcap_le(records))
        assert result["packet_count"] == 8
        assert len(result["packets"]) == 5

    def test_icmp_info(self):
        result = parse_capture_file(_pcap_le([(1000.0, ICMP_PING), (1000.5, ICMP_REPLY)]))
        infos = [p["info"] for p in result["packets"]]
        assert "request" in infos[0]
        assert "reply" in infos[1]
        assert result["protocol_stats"]["ICMP"] == 2

    def test_arp_info(self):
        result = parse_capture_file(_pcap_le([(1000.0, ARP_REQ)]))
        assert result["packets"][0]["protocol"] == "ARP"
        assert "who-has" in result["packets"][0]["info"]


class TestParsePcapNg:
    def test_pcapng_ethernet_classification(self):
        records = [(1000.0, TCP_SYN), (1000.5, DNS_Q)]
        result = parse_capture_file(_pcapng(records))
        assert result["packet_count"] == 2
        assert result["protocol_stats"]["HTTP"] == 1
        assert result["protocol_stats"]["DNS"] == 1
        assert len(result["packets"]) == 2

    def test_pcapng_empty(self):
        with pytest.raises(PcapParseError):
            parse_capture_file(_pcapng([]))


class TestInvalidFiles:
    def test_empty_file(self):
        with pytest.raises(PcapParseError):
            parse_capture_file(b"")

    def test_text_file(self):
        with pytest.raises(PcapParseError):
            parse_capture_file(b"this is not a pcap file at all")

    def test_bad_magic(self):
        with pytest.raises(PcapParseError):
            parse_capture_file(b"\x00" * 100)

    def test_too_small(self):
        with pytest.raises(PcapParseError):
            parse_capture_file(b"\xd4\xc3\xb2\xa1\x02\x00")

    def test_truncated_pcap_does_not_crash(self):
        data = _pcap_le([(1000.0, TCP_SYN), (1000.5, DNS_Q)])
        truncated = data[: len(data) - 10]
        result = parse_capture_file(truncated)
        assert result["packet_count"] >= 0
