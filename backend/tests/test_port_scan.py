import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.nmap_service import NmapHostResult, NmapPortResult, NmapScanResult
from app.services.port_scan_service import (
    SCAN_PROFILES,
    _upsert_port,
    _upsert_service,
    get_port_by_id,
    get_ports_by_host,
)


class TestScanProfiles:
    def test_top_ports_profile(self):
        profile = SCAN_PROFILES["top_ports"]
        assert profile["display_name"] == "Top 1000 Ports"
        assert profile["extra_args"] == ["--top-ports", "1000"]

    def test_custom_range_profile(self):
        profile = SCAN_PROFILES["custom_range"]
        assert profile["display_name"] == "Custom Port Range"
        assert profile["ports"] is None

    def test_all_ports_profile(self):
        profile = SCAN_PROFILES["all_ports"]
        assert profile["ports"] == "1-65535"


class TestPortScanRequestSchema:
    def test_valid_tcp_syn_top_ports(self):
        from app.schemas.port import PortScanRequest

        req = PortScanRequest(target="127.0.0.1", scan_type="tcp_syn", scan_profile="top_ports")
        assert req.scan_type == "tcp_syn"

    def test_custom_range_requires_ports(self):
        from pydantic import ValidationError

        from app.schemas.port import PortScanRequest

        with pytest.raises(ValidationError, match="Ports are required"):
            PortScanRequest(target="127.0.0.1", scan_type="tcp_syn", scan_profile="custom_range")

    def test_invalid_scan_type_rejected(self):
        from pydantic import ValidationError

        from app.schemas.port import PortScanRequest

        with pytest.raises(ValidationError):
            PortScanRequest(target="127.0.0.1", scan_type="version_detection", scan_profile="top_ports")

    def test_invalid_ports_rejected(self):
        from pydantic import ValidationError

        from app.schemas.port import PortScanRequest

        with pytest.raises(ValidationError, match="Ports must be"):
            PortScanRequest(target="127.0.0.1", scan_type="tcp_syn", scan_profile="custom_range", ports="80,foo")


class TestScanTypeValidation:
    @pytest.mark.asyncio
    async def test_handler_rejects_invalid_scan_type(self):
        from app.services.port_scan_service import port_scan_handler

        result = await port_scan_handler("test-id", "127.0.0.1", {"scan_type": "os_detection"})
        assert result["success"] is False
        assert "Invalid scan_type" in result["error"]

    @pytest.mark.asyncio
    async def test_handler_defaults_to_tcp_syn_when_blank(self):
        from app.services.port_scan_service import port_scan_handler

        with patch("app.services.port_scan_service.build_command") as mock_build:
            mock_build.return_value = ["nmap", "-sS", "127.0.0.1"]
            with patch("app.services.port_scan_service.async_session_factory") as mock_sf:
                mock_session = AsyncMock()
                mock_session.execute = AsyncMock()
                mock_session.execute.return_value = MagicMock()
                mock_session.execute.return_value.scalars = MagicMock(return_value=MagicMock())
                mock_session.execute.return_value.scalars.return_value.all.return_value = []
                mock_cm = MagicMock()
                mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
                mock_cm.__aexit__ = AsyncMock(return_value=None)
                mock_sf.return_value = mock_cm

                with patch("app.services.port_scan_service.host_discovery_handler") as mock_discovery:
                    mock_discovery.return_value = {"success": True, "summary": {"total_hosts_found": 0}}

                    result = await port_scan_handler("test-id", "127.0.0.1", {})
                    assert result["success"] is True
                    assert mock_build.call_args.args[0] == "tcp_syn"


class TestPortScanHandler:
    @pytest.mark.asyncio
    async def test_handler_no_alive_hosts(self):
        from app.services.port_scan_service import port_scan_handler

        with patch("app.services.port_scan_service.async_session_factory") as mock_sf:
            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_session.execute.return_value = MagicMock()
            mock_session.execute.return_value.scalars = MagicMock(return_value=MagicMock())
            mock_session.execute.return_value.scalars.return_value.all.return_value = []

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
            mock_cm.__aexit__ = AsyncMock(return_value=None)
            mock_sf.return_value = mock_cm

            with patch("app.services.port_scan_service.host_discovery_handler") as mock_discovery:
                mock_discovery.return_value = {"success": True, "summary": {"total_hosts_found": 0}}

                result = await port_scan_handler("test-id", "192.168.56.0/24", {"scan_type": "tcp_syn"})
                assert result["success"] is True
                assert result["summary"]["total_hosts_scanned"] == 0
                assert result["summary"]["total_ports_found"] == 0
                mock_discovery.assert_called_once()

    @pytest.mark.asyncio
    async def test_handler_bootstraps_hosts_when_none_exist(self):
        from app.services.port_scan_service import port_scan_handler

        assessment_id = str(uuid.uuid4())
        mock_host = MagicMock()
        mock_host.id = uuid.uuid4()
        mock_host.ip_address = "192.168.56.20"
        mock_host.is_alive = True

        empty_session = AsyncMock()
        empty_session.execute = AsyncMock()
        empty_session.execute.return_value = MagicMock()
        empty_session.execute.return_value.scalars = MagicMock(return_value=MagicMock())
        empty_session.execute.return_value.scalars.return_value.all.return_value = []

        hosts_session = AsyncMock()
        hosts_session.execute = AsyncMock()
        hosts_session.execute.return_value = MagicMock()
        hosts_session.execute.return_value.scalars = MagicMock(return_value=MagicMock())
        hosts_session.execute.return_value.scalars.return_value.all.return_value = [mock_host]

        upsert_session = AsyncMock()
        upsert_session.execute = AsyncMock()
        upsert_session.execute.return_value = MagicMock()
        upsert_session.execute.return_value.scalar_one_or_none.return_value = None
        upsert_session.commit = AsyncMock()
        upsert_session.add = MagicMock()
        upsert_session.flush = AsyncMock()

        meta_session = AsyncMock()
        meta_session.commit = AsyncMock()
        meta_session.add = MagicMock()
        meta_session.flush = AsyncMock()

        sessions = [empty_session, hosts_session, upsert_session, meta_session]
        session_idx = 0

        def enter_side_effect():
            nonlocal session_idx
            idx = session_idx
            session_idx += 1
            return sessions[idx]

        with patch("app.services.port_scan_service.async_session_factory") as mock_sf:
            mock_sf.return_value = MagicMock()
            mock_sf.return_value.__aenter__ = AsyncMock(side_effect=enter_side_effect)
            mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

            with patch("app.services.port_scan_service.host_discovery_handler") as mock_discovery:
                mock_discovery.return_value = {"success": True, "summary": {"total_hosts_found": 1}}

                with patch("app.services.port_scan_service.run_scan") as mock_scan:
                    mock_scan.return_value = NmapScanResult(
                        scan_type="tcp_syn", target="192.168.56.20",
                        hosts=[NmapHostResult(ip_address="192.168.56.20", status="up",
                            open_ports=[NmapPortResult(port=22, protocol="tcp", state="open", service_name="ssh")])],
                        duration_seconds=3.0,
                    )

                    result = await port_scan_handler(assessment_id, "192.168.56.0/24", {"scan_type": "tcp_syn"})
                    assert result["success"] is True
                    assert result["summary"]["total_hosts_scanned"] == 1
                    assert result["summary"]["total_ports_found"] == 1
                    mock_discovery.assert_called_once()
                    assert mock_discovery.call_args.kwargs["assessment_id"] == assessment_id

    @pytest.mark.asyncio
    async def test_handler_bootstrap_failure_returns_error(self):
        from app.services.port_scan_service import port_scan_handler

        with patch("app.services.port_scan_service.async_session_factory") as mock_sf:
            mock_session = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_session.execute.return_value = MagicMock()
            mock_session.execute.return_value.scalars = MagicMock(return_value=MagicMock())
            mock_session.execute.return_value.scalars.return_value.all.return_value = []

            mock_cm = MagicMock()
            mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
            mock_cm.__aexit__ = AsyncMock(return_value=None)
            mock_sf.return_value = mock_cm

            with patch("app.services.port_scan_service.host_discovery_handler") as mock_discovery:
                mock_discovery.return_value = {"success": False, "error": "discovery failed"}

                result = await port_scan_handler("test-id", "192.168.56.0/24", {"scan_type": "tcp_syn"})
                assert result["success"] is False
                assert result["error"] == "discovery failed"

    @pytest.mark.asyncio
    async def test_handler_with_alive_hosts_scan(self):
        from app.services.port_scan_service import port_scan_handler

        assessment_id = str(uuid.uuid4())
        mock_host = MagicMock()
        mock_host.id = uuid.uuid4()
        mock_host.ip_address = "192.168.56.20"
        mock_host.is_alive = True

        mock_outer_session = AsyncMock()
        mock_outer_session.execute = AsyncMock()
        mock_outer_session.execute.return_value = MagicMock()
        mock_outer_session.execute.return_value.scalars = MagicMock(return_value=MagicMock())
        mock_outer_session.execute.return_value.scalars.return_value.all.return_value = [mock_host]

        mock_inner_session = AsyncMock()
        mock_inner_session.execute = AsyncMock()
        mock_inner_session.execute.return_value = MagicMock()
        mock_inner_port = MagicMock()
        mock_inner_port.state = "open"
        mock_inner_session.execute.return_value.scalar_one_or_none.return_value = mock_inner_port
        mock_inner_session.commit = AsyncMock()

        mock_meta_session = AsyncMock()
        mock_meta_session.commit = AsyncMock()
        mock_meta_session.add = MagicMock()
        mock_meta_session.flush = AsyncMock()

        sessions = [mock_outer_session, mock_inner_session, mock_meta_session]
        session_idx = 0

        def enter_side_effect():
            nonlocal session_idx
            idx = session_idx
            session_idx += 1
            return sessions[idx]

        with patch("app.services.port_scan_service.async_session_factory") as mock_sf:
            mock_sf.return_value = MagicMock()
            mock_sf.return_value.__aenter__ = AsyncMock(side_effect=enter_side_effect)
            mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

            with patch("app.services.port_scan_service.run_scan") as mock_scan:
                mock_scan.return_value = NmapScanResult(
                    scan_type="tcp_syn", target="192.168.56.20",
                    hosts=[NmapHostResult(ip_address="192.168.56.20", status="up",
                        open_ports=[NmapPortResult(port=22, protocol="tcp", state="open", service_name="ssh")])],
                    duration_seconds=3.0,
                )

                result = await port_scan_handler(assessment_id, "192.168.56.0/24", {"scan_type": "tcp_syn"})
                assert result["success"] is True
                assert result["summary"]["total_hosts_scanned"] == 1
                assert result["summary"]["total_ports_found"] == 1


class TestUpsertPort:
    @pytest.mark.asyncio
    async def test_insert_new_port(self):
        host_id = uuid.uuid4()
        nmap_port = NmapPortResult(port=80, protocol="tcp", state="open", reason="syn-ack")

        mock_session = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        with patch("app.services.port_scan_service.select") as mock_select:
            mock_select.return_value.where.return_value = MagicMock()
            with patch("app.services.port_scan_service.Port") as MockPort:
                MockPort.return_value = MagicMock()
                result = await _upsert_port(mock_session, host_id, nmap_port)
                assert result is not None
                mock_session.add.assert_called_once()
                mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_existing_port(self):
        host_id = uuid.uuid4()
        nmap_port = NmapPortResult(port=22, protocol="tcp", state="open", reason="syn-ack")
        existing_port = MagicMock()
        existing_port.state = "filtered"
        existing_port.reason = None

        mock_session = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = existing_port

        result = await _upsert_port(mock_session, host_id, nmap_port)
        assert result.state == "open"
        assert result.reason == "syn-ack"


class TestUpsertService:
    @pytest.mark.asyncio
    async def test_insert_new_service(self):
        port_id = uuid.uuid4()
        nmap_port = NmapPortResult(
            port=80, protocol="tcp", state="open",
            service_name="http", product="Apache", version="2.4.41", extra_info="PHP 7.4",
        )

        mock_session = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        with patch("app.services.port_scan_service.select") as mock_select:
            mock_select.return_value.where.return_value = MagicMock()
            with patch("app.services.port_scan_service.Service") as MockService:
                MockService.return_value = MagicMock()
                result = await _upsert_service(mock_session, port_id, nmap_port)
                assert result is not None
                mock_session.add.assert_called_once()
                mock_session.flush.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_existing_service(self):
        port_id = uuid.uuid4()
        nmap_port = NmapPortResult(port=22, protocol="tcp", state="open", service_name="ssh", product="OpenSSH")
        existing_service = MagicMock()
        existing_service.name = "ssh"
        existing_service.product = "old-product"
        existing_service.version = None

        mock_session = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = existing_service

        result = await _upsert_service(mock_session, port_id, nmap_port)
        assert result.name == "ssh"
        assert result.product == "OpenSSH"


class TestGetPortsQueries:
    @pytest.mark.asyncio
    async def test_get_ports_by_host(self):
        mock_session = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars = MagicMock(return_value=MagicMock())
        mock_session.execute.return_value.scalars.return_value.all.return_value = [MagicMock(), MagicMock()]

        ports = await get_ports_by_host(mock_session, str(uuid.uuid4()))
        assert len(ports) == 2

    @pytest.mark.asyncio
    async def test_get_port_by_id_found(self):
        port_id = uuid.uuid4()
        mock_port = MagicMock()
        mock_port.id = port_id

        mock_session = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_port

        result = await get_port_by_id(mock_session, str(port_id))
        assert result is not None
        assert result.id == port_id

    @pytest.mark.asyncio
    async def test_get_port_by_id_not_found(self):
        mock_session = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalar_one_or_none.return_value = None

        result = await get_port_by_id(mock_session, str(uuid.uuid4()))
        assert result is None
