import ipaddress

import pytest

from app.services.nmap_service import (
    NmapHostResult,
    NmapPortResult,
    _is_local_target,
    build_command,
    parse_nmap_output,
)
from app.services.host_discovery_service import _is_invalid_discovery_address


SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sn -n 192.168.56.0/24" start="1234567890">
  <scaninfo type="ping" protocol="ip" numservices="0"/>
  <host>
    <status state="up" reason="echo-reply" reason_ttl="128"/>
    <address addr="192.168.56.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="host-machine" type="PTR"/>
    </hostnames>
    <times srtt="500" rttvar="100" to="100000"/>
  </host>
  <host>
    <status state="up" reason="echo-reply" reason_ttl="64"/>
    <address addr="08:00:27:ab:cd:20" addrtype="mac" vendor="PCS Systemtechnik GmbH"/>
    <address addr="192.168.56.20" addrtype="ipv4"/>
    <hostnames>
      <hostname name="metasploitable" type="PTR"/>
    </hostnames>
    <os>
      <osmatch name="Linux 2.6.9 - 2.6.33" accuracy="100"/>
    </os>
    <times srtt="400" rttvar="80" to="100000"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" method="table" conf="3"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="Apache httpd" version="2.2.8" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response" reason_ttl="0"/>
    <address addr="192.168.56.50" addrtype="ipv4"/>
    <hostnames/>
  </host>
</nmaprun>"""


class TestNmapXmlParsing:
    def test_parse_alive_host(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        alive = [h for h in hosts if h.status == "up"]
        assert len(alive) == 2

    def test_parse_down_host_excluded(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        down = [h for h in hosts if h.status == "down"]
        assert len(down) == 1

    def test_parse_ip_address(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        assert hosts[0].ip_address == "192.168.56.1"
        assert hosts[1].ip_address == "192.168.56.20"

    def test_parse_hostname(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        assert hosts[0].hostname == "host-machine"
        assert hosts[1].hostname == "metasploitable"

    def test_parse_mac_address(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        assert hosts[1].mac_address == "08:00:27:ab:cd:20"

    def test_parse_vendor(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        assert hosts[1].vendor == "PCS Systemtechnik GmbH"

    def test_parse_os_name(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        assert hosts[1].os_name == "Linux 2.6.9 - 2.6.33"

    def test_parse_os_accuracy(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        assert hosts[1].os_accuracy == 100

    def test_parse_latency(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        assert hosts[0].latency == 0.5
        assert hosts[1].latency == 0.4

    def test_parse_open_ports(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        ports = hosts[1].open_ports
        assert len(ports) == 3
        assert ports[0].port == 22
        assert ports[0].protocol == "tcp"
        assert ports[0].state == "open"

    def test_parse_filtered_port(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        ports = hosts[1].open_ports
        assert ports[2].state == "filtered"

    def test_parse_port_service_info(self):
        hosts = parse_nmap_output(SAMPLE_NMAP_XML)
        ports = hosts[1].open_ports
        ssh_port = ports[0]
        assert ssh_port.service_name == "ssh"
        http_port = ports[1]
        assert http_port.service_name == "http"
        assert http_port.product == "Apache httpd"
        assert http_port.version == "2.2.8"

    def test_parse_empty_xml(self):
        hosts = parse_nmap_output("<nmaprun></nmaprun>")
        assert len(hosts) == 0

    def test_parse_invalid_xml(self):
        hosts = parse_nmap_output("not xml")
        assert len(hosts) == 0


class TestNmapCommandBuilder:
    def test_ping_sweep_command(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.nmap_service._get_local_networks", lambda: []
        )
        cmd = build_command("ping_sweep", "192.168.56.0/24")
        assert "nmap" in cmd[0]
        assert "-sn" in cmd
        assert "-n" in cmd
        assert "--host-timeout" in cmd
        assert "--max-retries" in cmd
        assert "--max-rtt-timeout" in cmd
        assert "-PE" in cmd
        assert "-PR" not in cmd
        assert "192.168.56.0/24" in cmd

    def test_ping_sweep_local_subnet_uses_arp(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.nmap_service._get_local_networks",
            lambda: [ipaddress.ip_network("192.168.56.0/24")],
        )
        cmd = build_command("ping_sweep", "192.168.56.0/24")
        assert "-PR" in cmd
        assert "-PE" not in cmd

    def test_ping_sweep_remote_subnet_uses_icmp(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.nmap_service._get_local_networks",
            lambda: [ipaddress.ip_network("192.168.56.0/24")],
        )
        cmd = build_command("ping_sweep", "10.0.0.0/24")
        assert "-PE" in cmd
        assert "-PR" not in cmd

    def test_ping_sweep_remote_subnet_adds_tcp_probe(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.nmap_service._get_local_networks",
            lambda: [ipaddress.ip_network("192.168.56.0/24")],
        )
        cmd = build_command("ping_sweep", "10.0.0.0/24")
        assert "-PS80,443" in cmd

    def test_ping_sweep_local_subnet_does_not_add_tcp_probe(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.nmap_service._get_local_networks",
            lambda: [ipaddress.ip_network("192.168.56.0/24")],
        )
        cmd = build_command("ping_sweep", "192.168.56.0/24")
        assert "-PR" in cmd
        assert "-PE" not in cmd
        assert "-PS80,443" not in cmd

    def test_ping_sweep_local_single_host_uses_arp(self, monkeypatch):
        monkeypatch.setattr(
            "app.services.nmap_service._get_local_networks",
            lambda: [ipaddress.ip_network("192.168.56.0/24")],
        )
        cmd = build_command("ping_sweep", "192.168.56.20")
        assert "-PR" in cmd
        assert "-PE" not in cmd

    def test_arp_scan_command(self):
        cmd = build_command("arp_scan", "192.168.56.0/24")
        assert "-PR" in cmd

    def test_tcp_syn_with_ports(self):
        cmd = build_command("tcp_syn", "192.168.56.20", ports="22,80,443")
        assert "-p" in cmd
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "22,80,443"
        assert "-Pn" in cmd

    def test_unknown_scan_type_defaults_to_ping(self):
        cmd = build_command("unknown_type", "192.168.56.1")
        assert "-sn" in cmd

    def test_extra_args_included(self):
        cmd = build_command("ping_sweep", "192.168.56.0/24", extra_args=["--reason", "-T4"])
        assert "--reason" in cmd
        assert "-T4" in cmd

    def test_xml_output_flag(self):
        cmd = build_command("ping_sweep", "192.168.56.1")
        assert "-oX" in cmd
        assert "-" in cmd

    def test_tcp_connect_scan(self):
        cmd = build_command("tcp_connect", "192.168.56.20")
        assert "-sT" in cmd
        assert "-Pn" in cmd

    def test_version_detection_scan(self):
        cmd = build_command("version_detection", "192.168.56.20")
        assert "-sV" in cmd
        assert "-Pn" in cmd

    def test_vuln_scan(self):
        cmd = build_command("vuln_scan", "192.168.56.20")
        assert "-sV" in cmd
        assert "--script" in cmd
        assert "-Pn" in cmd

    def test_udp_scan_keeps_discovery(self):
        cmd = build_command("udp_scan", "192.168.56.20")
        assert "-sU" in cmd
        assert "-Pn" not in cmd


class TestLocalTargetDetection:
    LOCAL = [ipaddress.ip_network("192.168.56.0/24")]

    def test_cidr_in_local_subnet(self):
        assert _is_local_target("192.168.56.0/24", self.LOCAL) is True

    def test_single_ip_in_local_subnet(self):
        assert _is_local_target("192.168.56.20", self.LOCAL) is True

    def test_remote_private_subnet(self):
        assert _is_local_target("10.0.0.0/24", self.LOCAL) is False

    def test_remote_172_subnet(self):
        assert _is_local_target("172.16.5.0/24", self.LOCAL) is False

    def test_public_ip(self):
        assert _is_local_target("8.8.8.8", self.LOCAL) is False

    def test_range_start_in_local_subnet(self):
        assert _is_local_target("192.168.56.10-30", self.LOCAL) is True

    def test_range_start_remote(self):
        assert _is_local_target("10.0.0.10-30", self.LOCAL) is False

    def test_no_local_networks_returns_false(self):
        assert _is_local_target("192.168.56.0/24", []) is False

    def test_hostname_resolves_to_local_subnet(self):
        assert _is_local_target("192.168.56.100", self.LOCAL) is True

    def test_unresolvable_hostname_returns_false(self):
        assert _is_local_target("no-such-host.invalid", self.LOCAL) is False


class TestInvalidDiscoveryAddress:
    def test_broadcast_of_target_network(self):
        assert _is_invalid_discovery_address("192.168.0.255", "192.168.0.0/24") is True

    def test_network_address_of_target_network(self):
        assert _is_invalid_discovery_address("192.168.0.0", "192.168.0.0/24") is True

    def test_unicast_host_is_valid(self):
        assert _is_invalid_discovery_address("192.168.0.103", "192.168.0.0/24") is False

    def test_multicast_is_invalid(self):
        assert _is_invalid_discovery_address("224.0.0.22", "192.168.0.0/24") is True

    def test_limited_broadcast_is_invalid(self):
        assert _is_invalid_discovery_address("255.255.255.255", "192.168.0.0/24") is True

    def test_single_ip_target_keeps_host(self):
        assert _is_invalid_discovery_address("192.168.0.103", "192.168.0.103") is False

    def test_non_cidr_target_keeps_broadcast(self):
        assert _is_invalid_discovery_address("192.168.0.255", "192.168.0.255") is False


class TestNmapHostResult:
    def test_host_result_defaults(self):
        host = NmapHostResult(ip_address="192.168.56.1")
        assert host.ip_address == "192.168.56.1"
        assert host.hostname is None
        assert host.status == "unknown"
        assert host.open_ports == []

    def test_host_result_with_values(self):
        host = NmapHostResult(
            ip_address="192.168.56.20",
            hostname="test-host",
            status="up",
            latency=0.5,
            open_ports=[NmapPortResult(port=22, protocol="tcp", state="open")],
        )
        assert host.hostname == "test-host"
        assert host.latency == 0.5
        assert len(host.open_ports) == 1
        assert host.open_ports[0].port == 22
        assert host.open_ports[0].protocol == "tcp"
        assert host.open_ports[0].state == "open"


class TestNmapPortResult:
    def test_port_result_defaults(self):
        p = NmapPortResult(port=80)
        assert p.port == 80
        assert p.protocol == "tcp"
        assert p.state == "unknown"
        assert p.service_name is None

    def test_port_result_with_service(self):
        p = NmapPortResult(
            port=443, protocol="tcp", state="open",
            service_name="https", product="nginx", version="1.24.0",
        )
        assert p.service_name == "https"
        assert p.product == "nginx"
        assert p.version == "1.24.0"
