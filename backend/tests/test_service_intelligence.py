import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.port import Port
from app.models.service import Service
from app.services.service_intelligence_service import (
    CATEGORY_MAP,
    SERVICE_NAME_MAP,
    calculate_confidence,
    categorize_service,
    enrich_service,
    extract_normalized_version,
    extract_os_from_version,
    generate_notes,
    normalize_product,
    normalize_service_name,
    service_intelligence_handler,
)


class TestServiceNormalization:
    def test_normalize_http_variants(self):
        assert normalize_service_name("http") == "HTTP"
        assert normalize_service_name("HTTP") == "HTTP"
        assert normalize_service_name("www") == "HTTP"
        assert normalize_service_name("http-proxy") == "HTTP"

    def test_normalize_https(self):
        assert normalize_service_name("https") == "HTTPS"
        assert normalize_service_name("HTTPS") == "HTTPS"

    def test_normalize_smb(self):
        assert normalize_service_name("microsoft-ds") == "SMB"
        assert normalize_service_name("netbios-ssn") == "SMB"

    def test_normalize_rdp(self):
        assert normalize_service_name("ms-wbt-server") == "RDP"
        assert normalize_service_name("rdp") == "RDP"

    def test_normalize_dns(self):
        assert normalize_service_name("domain") == "DNS"

    def test_normalize_ssh(self):
        assert normalize_service_name("ssh") == "SSH"
        assert normalize_service_name("SSH") == "SSH"

    def test_normalize_mysql(self):
        assert normalize_service_name("mysql") == "MySQL"

    def test_normalize_postgresql(self):
        assert normalize_service_name("postgresql") == "PostgreSQL"
        assert normalize_service_name("pgsql") == "PostgreSQL"

    def test_normalize_ftp(self):
        assert normalize_service_name("ftp") == "FTP"

    def test_normalize_smtp(self):
        assert normalize_service_name("smtp") == "SMTP"

    def test_normalize_imap(self):
        assert normalize_service_name("imap") == "IMAP"

    def test_normalize_pop3(self):
        assert normalize_service_name("pop3") == "POP3"

    def test_normalize_unknown_service(self):
        assert normalize_service_name("unknown-custom") == "unknown-custom"

    def test_normalize_none(self):
        assert normalize_service_name(None) is None

    def test_normalize_empty_string(self):
        assert normalize_service_name("") is None

    def test_normalize_whitespace(self):
        assert normalize_service_name("  ssh  ") == "SSH"
        assert normalize_service_name("  HTTP  ") == "HTTP"


class TestProductNormalization:
    def test_normalize_apache_httpd(self):
        assert normalize_product("Apache httpd") == "Apache HTTP Server"
        assert normalize_product("apache httpd") == "Apache HTTP Server"
        assert normalize_product("APACHE HTTPD") == "Apache HTTP Server"

    def test_normalize_apache(self):
        assert normalize_product("Apache") == "Apache HTTP Server"

    def test_normalize_nginx(self):
        assert normalize_product("nginx") == "NGINX"
        assert normalize_product("NGINX") == "NGINX"

    def test_normalize_openssh(self):
        assert normalize_product("OpenSSH") == "OpenSSH"
        assert normalize_product("openssh") == "OpenSSH"

    def test_normalize_mysql(self):
        assert normalize_product("MySQL") == "MySQL Server"
        assert normalize_product("mysql") == "MySQL Server"

    def test_normalize_samba(self):
        assert normalize_product("Samba") == "Samba"
        assert normalize_product("smbd") == "Samba"

    def test_normalize_vsftpd(self):
        assert normalize_product("vsFTPd") == "vsFTPd"
        assert normalize_product("vsftpd") == "vsFTPd"

    def test_normalize_unknown_product(self):
        assert normalize_product("Custom Product v2") == "Custom Product v2"

    def test_normalize_none(self):
        assert normalize_product(None) is None

    def test_normalize_whitespace(self):
        assert normalize_product("  nginx  ") == "NGINX"


class TestCategoryMapping:
    def test_web_server(self):
        assert categorize_service("HTTP") == "Web Server"
        assert categorize_service("HTTPS") == "Web Server"

    def test_remote_access(self):
        assert categorize_service("SSH") == "Remote Access"
        assert categorize_service("RDP") == "Remote Access"
        assert categorize_service("Telnet") == "Remote Access"
        assert categorize_service("VNC") == "Remote Access"

    def test_database(self):
        assert categorize_service("MySQL") == "Database"
        assert categorize_service("PostgreSQL") == "Database"
        assert categorize_service("MSSQL") == "Database"
        assert categorize_service("Redis") == "Database"

    def test_mail(self):
        assert categorize_service("SMTP") == "Mail"
        assert categorize_service("POP3") == "Mail"
        assert categorize_service("IMAP") == "Mail"

    def test_file_sharing(self):
        assert categorize_service("FTP") == "File Sharing"
        assert categorize_service("SMB") == "File Sharing"
        assert categorize_service("NFS") == "File Sharing"

    def test_network_management(self):
        assert categorize_service("SNMP") == "Network Management"
        assert categorize_service("NTP") == "Network Management"

    def test_unknown_category(self):
        assert categorize_service("UnknownService") == "Other"

    def test_none(self):
        assert categorize_service(None) is None

    def test_all_mapped_services_have_categories(self):
        for name in SERVICE_NAME_MAP.values():
            if name not in CATEGORY_MAP:
                pytest.fail(f"Service '{name}' has no category mapping")


class TestVersionHandling:
    def test_extract_simple_version(self):
        assert extract_normalized_version("2.4.57") == "2.4.57"

    def test_extract_version_with_prefix(self):
        assert extract_normalized_version("Apache 2.4.57") == "2.4.57"

    def test_extract_openssh_version(self):
        assert extract_normalized_version("OpenSSH_8.9p1 Ubuntu") == "8.9p1"

    def test_extract_single_number(self):
        assert extract_normalized_version("1.0") == "1.0"

    def test_extract_version_with_patch(self):
        assert extract_normalized_version("7.0.0-p1") == "7.0.0-p1"

    def test_extract_none(self):
        assert extract_normalized_version(None) is None

    def test_extract_empty(self):
        assert extract_normalized_version("") is None

    def test_extract_no_version_string(self):
        assert extract_normalized_version("Apache HTTP Server") is not None

    def test_extract_os_ubuntu(self):
        assert extract_os_from_version("OpenSSH_8.9p1 Ubuntu-3") == "Ubuntu"

    def test_extract_os_debian(self):
        assert extract_os_from_version("Apache/2.4.41 Debian") == "Debian"

    def test_extract_os_windows(self):
        assert extract_os_from_version("IIS 10.0 Windows Server") == "Windows"

    def test_extract_os_none(self):
        assert extract_os_from_version("2.4.57") is None

    def test_extract_os_none_input(self):
        assert extract_os_from_version(None) is None


class TestConfidenceScoring:
    def test_known_service_product_version(self):
        assert calculate_confidence("SSH", "OpenSSH", "8.9p1") == 98

    def test_known_service_product_no_version(self):
        assert calculate_confidence("SSH", "OpenSSH", None) == 92

    def test_known_service_only(self):
        assert calculate_confidence("HTTP", None, None) == 85

    def test_product_only(self):
        assert calculate_confidence(None, "Apache HTTP Server", None) == 70

    def test_version_only(self):
        assert calculate_confidence(None, None, "2.4.57") == 60

    def test_unknown(self):
        assert calculate_confidence(None, None, None) == 30


class TestEnrichService:
    def _make_mock_service(self, **kwargs):
        service = MagicMock(spec=Service)
        service.id = uuid.uuid4()
        service.port_id = uuid.uuid4()
        service.name = None
        service.product = None
        service.version = None
        service.extra_info = None
        service.tunnel = None
        service.protocol = None
        service.banner = None
        service.normalized_name = None
        service.normalized_product = None
        service.normalized_version = None
        service.category = None
        service.confidence = None
        service.notes = None
        for k, v in kwargs.items():
            setattr(service, k, v)
        return service

    def test_enrich_http_service(self):
        service = self._make_mock_service(
            name="http",
            product="Apache httpd",
            version="Apache 2.4.57",
        )
        enrich_service(service)
        assert service.normalized_name == "HTTP"
        assert service.normalized_product == "Apache HTTP Server"
        assert service.normalized_version == "2.4.57"
        assert service.category == "Web Server"
        assert service.confidence == 98
        assert service.notes is not None

    def test_enrich_ssh_service(self):
        service = self._make_mock_service(
            name="ssh",
            product="OpenSSH",
            version="OpenSSH_8.9p1 Ubuntu",
        )
        enrich_service(service)
        assert service.normalized_name == "SSH"
        assert service.normalized_product == "OpenSSH"
        assert service.normalized_version == "8.9p1"
        assert service.category == "Remote Access"
        assert service.confidence == 98

    def test_enrich_smb_service(self):
        service = self._make_mock_service(
            name="microsoft-ds",
            product="Samba",
            version="4.15.0",
        )
        enrich_service(service)
        assert service.normalized_name == "SMB"
        assert service.normalized_product == "Samba"
        assert service.category == "File Sharing"

    def test_enrich_unknown_service(self):
        service = self._make_mock_service(name="custom-app")
        enrich_service(service)
        assert service.normalized_name == "custom-app"
        assert service.normalized_product is None
        assert service.normalized_version is None
        assert service.category == "Other"
        assert service.confidence == 85

    def test_enrich_service_no_normalization_needed(self):
        service = self._make_mock_service(
            name="SSH",
            product="OpenSSH",
            version="8.9",
        )
        enrich_service(service)
        assert service.normalized_name == "SSH"
        assert service.notes is None

    def test_notes_generated(self):
        notes = generate_notes(
            original_name="http",
            original_product="Apache httpd",
            original_version="Apache 2.4.57",
            normalized_name="HTTP",
            normalized_product="Apache HTTP Server",
            os_from_version=None,
        )
        assert "Normalized from 'http' to 'HTTP'" in notes
        assert "Product normalized from 'Apache httpd' to 'Apache HTTP Server'" in notes

    def test_notes_with_os(self):
        notes = generate_notes(
            original_name="ssh",
            original_product="OpenSSH",
            original_version="OpenSSH_8.9p1 Ubuntu",
            normalized_name="SSH",
            normalized_product="OpenSSH",
            os_from_version="Ubuntu",
        )
        assert "OS detected from version string: Ubuntu" in notes

    def test_notes_none_when_no_changes(self):
        notes = generate_notes(
            original_name="SSH",
            original_product="OpenSSH",
            original_version="8.9",
            normalized_name="SSH",
            normalized_product="OpenSSH",
            os_from_version=None,
        )
        assert notes is None


class TestServiceIntelligenceHandler:
    @pytest.mark.asyncio
    async def test_handler_no_services(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.all.return_value = []

        with patch("app.services.service_intelligence_service.async_session_factory") as mock_sf:
            mock_sf.return_value = MagicMock()
            mock_sf.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await service_intelligence_handler(str(uuid.uuid4()), "192.168.56.0/24")
            assert result["success"] is True
            assert result["summary"]["total_services"] == 0
            assert result["summary"]["total_enriched"] == 0

    @pytest.mark.asyncio
    async def test_handler_with_services(self):
        service_id = uuid.uuid4()
        port_id = uuid.uuid4()
        host_id = uuid.uuid4()
        assessment_uuid = uuid.uuid4()

        mock_port = MagicMock(spec=Port)
        mock_port.id = port_id
        mock_port.host_id = host_id
        mock_port.port = 80
        mock_port.protocol = "tcp"
        mock_port.host = MagicMock()
        mock_port.host.id = host_id
        mock_port.host.ip_address = "192.168.56.20"
        mock_port.host.hostname = "metasploitable"

        mock_service = MagicMock(spec=Service)
        mock_service.id = service_id
        mock_service.port_id = port_id
        mock_service.name = "http"
        mock_service.product = "Apache httpd"
        mock_service.version = "Apache 2.4.57"
        mock_service.extra_info = None
        mock_service.tunnel = None
        mock_service.protocol = None
        mock_service.banner = None
        mock_service.normalized_name = None
        mock_service.normalized_product = None
        mock_service.normalized_version = None
        mock_service.category = None
        mock_service.confidence = None
        mock_service.notes = None
        mock_service.port = mock_port

        fetch_session = AsyncMock()
        fetch_session.execute = AsyncMock()
        fetch_session.execute.return_value = MagicMock()
        fetch_session.execute.return_value.scalars.return_value.all.return_value = [mock_service]

        write_session = AsyncMock()
        write_session.commit = AsyncMock()
        write_session.add = MagicMock()

        sessions = [fetch_session, write_session]
        session_idx = 0

        def enter_side_effect():
            nonlocal session_idx
            idx = session_idx
            session_idx += 1
            return sessions[idx]

        with patch("app.services.service_intelligence_service.async_session_factory") as mock_sf:
            mock_sf.return_value = MagicMock()
            mock_sf.return_value.__aenter__ = AsyncMock(side_effect=enter_side_effect)
            mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await service_intelligence_handler(str(assessment_uuid), "192.168.56.0/24")
            assert result["success"] is True
            assert result["summary"]["total_services"] == 1
            assert result["summary"]["total_enriched"] == 1
            assert "Web Server" in result["summary"]["categories"]
            assert result["summary"]["confidence_distribution"]["high"] == 1

    @pytest.mark.asyncio
    async def test_handler_with_tracker(self):
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.execute.return_value = MagicMock()
        mock_session.execute.return_value.scalars.return_value.all.return_value = []

        mock_tracker = MagicMock()

        with patch("app.services.service_intelligence_service.async_session_factory") as mock_sf:
            mock_sf.return_value = MagicMock()
            mock_sf.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_sf.return_value.__aexit__ = AsyncMock(return_value=None)
            result = await service_intelligence_handler(
                str(uuid.uuid4()), "192.168.56.0/24", tracker=mock_tracker
            )
            assert result["success"] is True
            mock_tracker.update_stage_status.assert_called()
            mock_tracker.update_stage_progress.assert_called()
