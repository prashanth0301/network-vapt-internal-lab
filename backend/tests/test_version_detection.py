import tempfile
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.nmap_service import (
    NmapHostResult,
    NmapPortResult,
    NmapScanResult,
    parse_nmap_output,
)
from app.services.scanner.nmap_vuln import NmapVulnScanner
from app.services.scanner_manager import scanner_manager


BANNER_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.56.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" method="probed" conf="10"/>
        <script id="banner" output="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0" method="table" conf="3">
          <banner>HTTP/1.1 200 OK</banner>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>"""

VULN_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.56.20" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.49" method="probed" conf="10"/>
        <script id="http-vuln-cve2021-41773" output="VULNERABLE: Path traversal. CVSS Score: 9.8. CVE-2021-41773"/>
        <script id="banner" output="HTTP/1.1 200 OK"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="Apache httpd" version="2.4.49" method="probed" conf="10"/>
        <script id="vulners" output="cpe:/a:apache:http_server:2.4.49
CVE-2021-41773 9.8 https://vulners.com/cve/CVE-2021-41773
CVE-2021-44228 10.0 https://vulners.com/cve/CVE-2021-44228"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" method="table" conf="3"/>
        <script id="smb-vuln-ms17-010" output="VULNERABLE: SMB remote code execution CVE-2017-0143"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
        <script id="http-shellshock" output="NOT VULNERABLE: script did not detect the vulnerability"/>
      </port>
    </ports>
    <hostscript>
      <script id="smb2-vuln-ms17-010" output="VULNERABLE: CVE-2017-0143 SMBv2 remote code execution"/>
    </hostscript>
  </host>
</nmaprun>"""


class TestBannerExtraction:
    def test_banner_from_script_element(self):
        hosts = parse_nmap_output(BANNER_XML)
        ssh_port = hosts[0].open_ports[0]
        assert ssh_port.banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

    def test_method_not_used_as_banner(self):
        hosts = parse_nmap_output(BANNER_XML)
        http_port = hosts[0].open_ports[1]
        assert http_port.banner is None
        assert http_port.service_name == "http"
        assert http_port.product == "Apache httpd"

    def test_legacy_banner_child_element(self):
        hosts = parse_nmap_output(BANNER_XML)
        https_port = hosts[0].open_ports[2]
        assert https_port.banner == "HTTP/1.1 200 OK"
        assert https_port.version == "1.18.0"


class TestVersionDetectionPhase:
    @pytest.mark.asyncio
    async def test_disabled_via_parameters(self):
        from app.services.service_intelligence_service import _run_version_detection

        result = await _run_version_detection(
            str(uuid.uuid4()), {"version_scan_enabled": False}, None
        )
        assert result["skipped"] is True

    @pytest.mark.asyncio
    async def test_merge_version_and_os(self):
        from app.services.service_intelligence_service import _run_version_detection

        assessment_id = str(uuid.uuid4())
        host = MagicMock()
        host.id = uuid.uuid4()
        host.ip_address = "192.168.56.20"
        host.os_name = None
        host.os_version = None
        host.os_accuracy = None

        mock_port = MagicMock()
        mock_port.port = 22
        mock_port.protocol = "tcp"
        mock_port.state = "open"
        host.ports = [mock_port]

        hosts_result = MagicMock()
        hosts_result.unique.return_value = hosts_result
        hosts_result.scalars.return_value.all.return_value = [host]

        hosts_session = AsyncMock()
        hosts_session.execute = AsyncMock(return_value=hosts_result)

        merge_session = AsyncMock()
        merge_session.commit = AsyncMock()
        merge_session.flush = AsyncMock()
        merge_session.add = MagicMock()

        sessions = [hosts_session, merge_session]
        session_idx = 0

        def enter_side_effect():
            nonlocal session_idx
            idx = session_idx
            session_idx += 1
            return sessions[idx]

        scanned_host = NmapHostResult(
            ip_address="192.168.56.20",
            status="up",
            os_name="Linux 3.2",
            os_accuracy=92,
            open_ports=[
                NmapPortResult(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service_name="ssh",
                    product="OpenSSH",
                    version="6.0p1",
                    extra_info="protocol 2.0",
                    banner="SSH-2.0-OpenSSH_6.0p1 Debian-1",
                )
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.services.service_intelligence_service.async_session_factory") as mock_sf:
                mock_sf.return_value = MagicMock()
                mock_sf.return_value.__aenter__ = AsyncMock(side_effect=enter_side_effect)
                mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

                with patch(
                    "app.services.service_intelligence_service.run_scan",
                    new=AsyncMock(
                        return_value=NmapScanResult(
                            scan_type="version_detection",
                            target="192.168.56.20",
                            hosts=[scanned_host],
                            duration_seconds=2.0,
                        )
                    ),
                ) as mock_run_scan:
                    with patch(
                        "app.services.service_intelligence_service._upsert_port",
                        new=AsyncMock(return_value=MagicMock(id=uuid.uuid4())),
                    ) as mock_upsert_port:
                        with patch(
                            "app.services.service_intelligence_service._upsert_service",
                            new=AsyncMock(return_value=MagicMock(id=uuid.uuid4())),
                        ) as mock_upsert_service:
                            with patch(
                                "app.services.service_intelligence_service.artifact_manager.create_stage_directory",
                                return_value=Path(tmpdir),
                            ):
                                summary = await _run_version_detection(assessment_id, {}, None)

        assert summary["skipped"] is False
        assert summary["hosts_scanned"] == 1
        assert summary["ports_fingerprinted"] == 1
        assert summary["services_enriched"] == 1
        assert summary["os_updated"] == 1
        assert mock_run_scan.await_count == 1
        assert mock_run_scan.await_args.kwargs["scan_type"] == "version_detection"
        assert mock_run_scan.await_args.kwargs["ports"] == "22"
        assert mock_run_scan.await_args.kwargs["extra_args"] == ["-O", "--osscan-guess"]
        assert mock_upsert_port.await_count == 1
        upserted_arg = mock_upsert_service.await_args.args[2]
        assert upserted_arg.product == "OpenSSH"
        assert upserted_arg.version == "6.0p1"
        assert upserted_arg.banner == "SSH-2.0-OpenSSH_6.0p1 Debian-1"
        assert host.os_name == "Linux 3.2"
        assert host.os_accuracy == 92

    @pytest.mark.asyncio
    async def test_skipped_when_no_open_ports(self):
        from app.services.service_intelligence_service import _run_version_detection

        host = MagicMock()
        host.id = uuid.uuid4()
        host.ip_address = "192.168.56.20"
        mock_port = MagicMock()
        mock_port.port = 22
        mock_port.protocol = "tcp"
        mock_port.state = "filtered"
        host.ports = [mock_port]

        hosts_result = MagicMock()
        hosts_result.unique.return_value = hosts_result
        hosts_result.scalars.return_value.all.return_value = [host]

        hosts_session = AsyncMock()
        hosts_session.execute = AsyncMock(return_value=hosts_result)

        with patch("app.services.service_intelligence_service.async_session_factory") as mock_sf:
            mock_sf.return_value = MagicMock()
            mock_sf.return_value.__aenter__ = AsyncMock(return_value=hosts_session)
            mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

            with patch("app.services.service_intelligence_service.run_scan") as mock_run_scan:
                summary = await _run_version_detection(str(uuid.uuid4()), {}, None)

        assert summary["skipped"] is True
        assert summary["reason"] == "no open TCP ports to fingerprint"
        mock_run_scan.assert_not_called()


class TestNmapVulnScanner:
    def setup_method(self):
        self.scanner = NmapVulnScanner()

    def test_vulners_script_creates_per_cve_findings(self):
        findings = self.scanner._parse_findings(VULN_XML, "192.168.56.20")
        vulners = [f for f in findings if f.scanner_id == "vulners"]
        assert len(vulners) == 2
        by_cve = {f.cve_ids[0]: f for f in vulners}
        assert "CVE-2021-41773" in by_cve
        assert by_cve["CVE-2021-41773"].cvss_score == 9.8
        assert by_cve["CVE-2021-41773"].severity == "Critical"
        assert by_cve["CVE-2021-44228"].cvss_score == 10.0
        assert by_cve["CVE-2021-44228"].affected_product == "Apache httpd"
        assert by_cve["CVE-2021-44228"].affected_version == "2.4.49"
        assert by_cve["CVE-2021-41773"].port == 443

    def test_vuln_script_finding(self):
        findings = self.scanner._parse_findings(VULN_XML, "192.168.56.20")
        http_vuln = [f for f in findings if f.scanner_id == "http-vuln-cve2021-41773"]
        assert len(http_vuln) == 1
        assert http_vuln[0].cve_ids == ["CVE-2021-41773"]
        assert http_vuln[0].cvss_score == 9.8
        assert http_vuln[0].severity == "Critical"
        assert http_vuln[0].port == 80
        assert http_vuln[0].affected_product == "Apache httpd"

    def test_hostscript_finding(self):
        findings = self.scanner._parse_findings(VULN_XML, "192.168.56.20")
        hostscript = [f for f in findings if f.scanner_id == "smb2-vuln-ms17-010"]
        assert len(hostscript) == 1
        assert hostscript[0].port is None
        assert "CVE-2017-0143" in hostscript[0].cve_ids

    def test_banner_and_not_vulnerable_ignored(self):
        findings = self.scanner._parse_findings(VULN_XML, "192.168.56.20")
        assert all(f.scanner_id != "banner" for f in findings)
        assert all(f.scanner_id != "http-shellshock" for f in findings)
        assert len(findings) == 5

    @pytest.mark.asyncio
    async def test_run_scan_returns_findings(self):
        from app.services.scanner.base import ScannerStatus

        with patch("app.services.scanner.nmap_vuln.run_scan") as mock_run_scan:
            mock_run_scan.return_value = NmapScanResult(
                scan_type="vuln_scan",
                target="192.168.56.20",
                raw_output=VULN_XML,
                duration_seconds=3.0,
            )
            result = await self.scanner.run_scan("192.168.56.20", ports="80,443,445,8080")

        assert result.status == ScannerStatus.COMPLETED
        assert len(result.findings) == 5
        assert result.duration_seconds == 3.0
        cmd = mock_run_scan.await_args.kwargs
        assert cmd["scan_type"] == "vuln_scan"
        assert cmd["ports"] == "80,443,445,8080"

    @pytest.mark.asyncio
    async def test_run_scan_without_ports(self):
        from app.services.scanner.base import ScannerStatus

        result = await self.scanner.run_scan("192.168.56.20")
        assert result.status == ScannerStatus.COMPLETED
        assert result.findings == []
        assert "No open ports" in (result.error or "")

    @pytest.mark.asyncio
    async def test_run_scan_error_propagates(self):
        from app.services.scanner.base import ScannerStatus

        with patch("app.services.scanner.nmap_vuln.run_scan") as mock_run_scan:
            mock_run_scan.return_value = NmapScanResult(
                scan_type="vuln_scan",
                target="192.168.56.20",
                error="nmap failed",
            )
            result = await self.scanner.run_scan("192.168.56.20", ports="80")

        assert result.status == ScannerStatus.FAILED
        assert result.findings == []
        assert "nmap failed" in (result.error or "")

    def test_registered_in_scanner_manager(self):
        assert "nmap" in scanner_manager.list_scanners()
        registered = scanner_manager.get_scanner("nmap")
        assert isinstance(registered, NmapVulnScanner)


class TestDefaultScannerFallback:
    @pytest.mark.asyncio
    async def test_unknown_scanner_falls_back_to_nmap(self):
        from app.services.scanner.base import ScanResult, ScannerStatus
        from app.services.vulnerability_assessment_service import vulnerability_assessment_handler

        mock_host = MagicMock()
        mock_host.id = uuid.uuid4()
        mock_host.ip_address = "192.168.56.20"

        sessions = []
        for i in range(4):
            s = AsyncMock()
            s.execute = AsyncMock()
            s.execute.return_value = MagicMock()
            s.execute.return_value.scalars.return_value.all.return_value = [mock_host] if i == 0 else []
            sessions.append(s)

        session_idx = 0

        def enter_side_effect():
            nonlocal session_idx
            idx = session_idx
            session_idx += 1
            return sessions[idx % len(sessions)]

        nmap_scanner = AsyncMock()
        nmap_scanner.name = "nmap"
        nmap_scanner.run_scan = AsyncMock(
            return_value=ScanResult(
                scan_id="test",
                status=ScannerStatus.COMPLETED,
                findings=[],
            )
        )

        def fake_get(name):
            return nmap_scanner if name == "nmap" else None

        with patch("app.services.vulnerability_assessment_service.scanner_manager") as mock_sm:
            mock_sm.get_scanner.side_effect = fake_get
            with patch("app.services.vulnerability_assessment_service.artifact_manager") as mock_am:
                mock_am.create_stage_directory.return_value = MagicMock()
                mock_am.save_metadata = MagicMock()
                mock_am.save_json = MagicMock()
                mock_am.save_error = MagicMock()
                mock_am.store_metadata = AsyncMock()
                with patch(
                    "app.services.vulnerability_assessment_service.async_session_factory"
                ) as mock_sf:
                    mock_sf.return_value = MagicMock()
                    mock_sf.return_value.__aenter__ = AsyncMock(side_effect=enter_side_effect)
                    mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

                    result = await vulnerability_assessment_handler(
                        str(uuid.uuid4()),
                        "192.168.56.0/24",
                        {"scanner": "openvas"},
                    )

        assert result["success"] is True
        assert result["summary"]["total_hosts"] == 1
        nmap_scanner.run_scan.assert_awaited_once()
        assert ("openvas",) in [c.args for c in mock_sm.get_scanner.call_args_list]
        assert ("nmap",) in [c.args for c in mock_sm.get_scanner.call_args_list]
