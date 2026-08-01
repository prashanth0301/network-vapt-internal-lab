import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.asyncio import AsyncSession


from app.core.database import async_session_factory
from app.models.host import Host
from app.models.port import Port
from app.models.service import Service
from app.services.artifact_manager import artifact_manager
from app.services.assessment.lifecycle import StageStatus
from app.services.assessment.progress_tracker import ProgressTracker

SERVICE_NAME_MAP = {
    "http": "HTTP",
    "http-proxy": "HTTP",
    "www": "HTTP",
    "https": "HTTPS",
    "microsoft-ds": "SMB",
    "netbios-ssn": "SMB",
    "ms-wbt-server": "RDP",
    "rdp": "RDP",
    "domain": "DNS",
    "ssh": "SSH",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "pgsql": "PostgreSQL",
    "ftp": "FTP",
    "smtp": "SMTP",
    "imap": "IMAP",
    "pop3": "POP3",
    "telnet": "Telnet",
    "ldap": "LDAP",
    "ldaps": "LDAPS",
    "nfs": "NFS",
    "nfsd": "NFS",
    "mssql": "MSSQL",
    "ms-sql-s": "MSSQL",
    "ms-sql": "MSSQL",
    "oracle-tns": "Oracle DB",
    "mongodb": "MongoDB",
    "redis": "Redis",
    "memcached": "Memcached",
    "snmp": "SNMP",
    "ntp": "NTP",
    "dhcp": "DHCP",
    "dhcpv6": "DHCP",
    "tftp": "TFTP",
    "rsync": "Rsync",
    "vnc": "VNC",
    "x11": "X11",
    "sip": "SIP",
    "rpc": "RPC",
    "dcom": "DCOM",
    "winrm": "WinRM",
    "kerberos": "Kerberos",
    "kpasswd": "Kerberos",
    "svn": "SVN",
    "git": "Git",
    "mqtt": "MQTT",
    "amqp": "AMQP",
    "stomp": "STOMP",
    "cassandra": "Cassandra",
    "elasticsearch": "Elasticsearch",
    "kafka": "Kafka",
    "zookeeper": "ZooKeeper",
    "docker": "Docker",
    "kubernetes": "Kubernetes",
    "etcd": "etcd",
    "consul": "Consul",
    "vault": "Vault",
    "ntp": "NTP",
    "ipp": "IPP",
    "syslog": "Syslog",
    "radius": "RADIUS",
    "wsman": "WS-Management",
}

PRODUCT_MAP = {
    "apache httpd": "Apache HTTP Server",
    "apache": "Apache HTTP Server",
    "apache tomcat": "Apache Tomcat",
    "tomcat": "Apache Tomcat",
    "nginx": "NGINX",
    "iis": "Microsoft IIS",
    "microsoft iis": "Microsoft IIS",
    "openssh": "OpenSSH",
    "mysql": "MySQL Server",
    "mariadb": "MariaDB Server",
    "postgresql": "PostgreSQL Server",
    "postgres": "PostgreSQL Server",
    "samba": "Samba",
    "smbd": "Samba",
    "vsftpd": "vsFTPd",
    "proftpd": "ProFTPD",
    "pure-ftpd": "Pure-FTPd",
    "nginx": "NGINX",
    "lighttpd": "Lighttpd",
    "node.js": "Node.js",
    "express": "Express.js",
    "django": "Django",
    "flask": "Flask",
    "ruby": "Ruby",
    "unicorn": "Unicorn",
    "gunicorn": "Gunicorn",
    "jetty": "Eclipse Jetty",
    "jboss": "JBoss",
    "wildfly": "WildFly",
    "glassfish": "Oracle GlassFish",
    "weblogic": "Oracle WebLogic",
}

CATEGORY_MAP = {
    "HTTP": "Web Server",
    "HTTPS": "Web Server",
    "SSH": "Remote Access",
    "Telnet": "Remote Access",
    "RDP": "Remote Access",
    "VNC": "Remote Access",
    "X11": "Remote Access",
    "WinRM": "Remote Access",
    "WS-Management": "Network Management",
    "MySQL": "Database",
    "PostgreSQL": "Database",
    "MSSQL": "Database",
    "Oracle DB": "Database",
    "MongoDB": "Database",
    "Cassandra": "Database",
    "Redis": "Database",
    "Memcached": "Caching",
    "Elasticsearch": "Database",
    "SMTP": "Mail",
    "POP3": "Mail",
    "IMAP": "Mail",
    "DNS": "DNS",
    "DHCP": "DNS",
    "FTP": "File Sharing",
    "SMB": "File Sharing",
    "NFS": "File Sharing",
    "TFTP": "File Sharing",
    "Rsync": "File Sharing",
    "LDAP": "Directory Services",
    "LDAPS": "Directory Services",
    "Kerberos": "Directory Services",
    "SNMP": "Network Management",
    "NTP": "Network Management",
    "RADIUS": "Network Management",
    "Syslog": "Network Management",
    "RPC": "Remote Access",
    "IPP": "Print Services",
    "SIP": "VoIP",
    "MQTT": "IoT",
    "AMQP": "Messaging",
    "STOMP": "Messaging",
    "Kafka": "Messaging",
    "ZooKeeper": "Coordination",
    "etcd": "Coordination",
    "Consul": "Coordination",
    "Vault": "Security",
    "DCOM": "Remote Access",
    "Git": "Version Control",
    "SVN": "Version Control",
    "Docker": "Container",
    "Kubernetes": "Orchestration",
}


def normalize_service_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    cleaned = name.strip().lower()
    return SERVICE_NAME_MAP.get(cleaned, name.strip())


def normalize_product(product: Optional[str]) -> Optional[str]:
    if not product:
        return None
    cleaned = product.strip().lower()
    return PRODUCT_MAP.get(cleaned, product.strip())


def extract_normalized_version(version_str: Optional[str]) -> Optional[str]:
    if not version_str:
        return None
    version_str = version_str.strip()
    match = re.search(r"(\d[\d\.]*[\da-zA-Z]*(?:[-_][a-zA-Z]*\d+)*)", version_str)
    if match:
        return match.group(1)
    return version_str


def extract_os_from_version(version_str: Optional[str]) -> Optional[str]:
    if not version_str:
        return None
    os_patterns = [
        r"(Ubuntu|Debian|CentOS|Red Hat|Fedora|Alpine|Arch|SUSE|FreeBSD|OpenBSD|NetBSD|Windows|macOS|Darwin|Solaris)",
    ]
    for pattern in os_patterns:
        match = re.search(pattern, version_str, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


_SSH_BANNER_RE = re.compile(r"SSH-2\.0-(OpenSSH)[_]?([^\s]+)?", re.IGNORECASE)
_FTP_BANNER_RE = re.compile(
    r"\b(vsftpd|proftpd|pure-ftpd|filezilla server)\b[^\d]*(\d+(?:\.\d+)*[a-zA-Z]?)?",
    re.IGNORECASE,
)
_PGSQL_BANNER_RE = re.compile(r"\bPostgreSQL\s+(\d+(?:\.\d+)*)", re.IGNORECASE)
_REDIS_BANNER_RE = re.compile(r"\bredis[_-]server[^\s]*\s+v?(\d+(?:\.\d+)*)", re.IGNORECASE)
_MONGODB_BANNER_RE = re.compile(r"\bMongoDB\s+(\d+(?:\.\d+)*)", re.IGNORECASE)
_HTTP_SERVER_HEADER_RE = re.compile(r"^[Ss]erver\s*:\s*(.+?)\s*$", re.MULTILINE)
_SMTP_PRODUCT_RE = re.compile(
    r"\b(Postfix|Exim|Sendmail|qmail|Microsoft ESMTP)\b", re.IGNORECASE
)
_PRODUCT_SLASH_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9._+ -]{1,60})/(\d[\w.+-]*)")
_BARE_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")


def analyze_banner(banner: Optional[str]) -> dict:
    result = {"product": None, "version": None, "os": None, "protocol": None}
    if not banner or not banner.strip():
        return result
    text = banner.strip()

    banner_lower = text.lower()
    if text.startswith("SSH-2.0"):
        result["protocol"] = "SSH"
    elif banner_lower.startswith(("220 ", "220-")):
        if any(k in banner_lower for k in ("ftp", "vsftpd", "proftpd")):
            result["protocol"] = "FTP"
        elif any(k in banner_lower for k in ("esmtp", "smtp", "postfix", "exim", "sendmail", "mail")):
            result["protocol"] = "SMTP"

    result["os"] = extract_os_from_version(text)

    match = _SSH_BANNER_RE.search(text)
    if match:
        result["product"] = match.group(1)
        if match.group(2):
            result["version"] = match.group(2).split(" ")[0]
        return result

    match = _PGSQL_BANNER_RE.search(text)
    if match:
        result["product"] = "PostgreSQL"
        result["version"] = match.group(1)
        return result

    match = _REDIS_BANNER_RE.search(text)
    if match:
        result["product"] = "Redis"
        result["version"] = match.group(1)
        return result

    match = _MONGODB_BANNER_RE.search(text)
    if match:
        result["product"] = "MongoDB"
        result["version"] = match.group(1)
        return result

    match = _FTP_BANNER_RE.search(text)
    if match:
        result["product"] = match.group(1)
        if match.group(2):
            result["version"] = match.group(2)
        return result

    match = _HTTP_SERVER_HEADER_RE.search(text)
    if match:
        server = match.group(1).strip()
        pm = re.match(r"([A-Za-z0-9._+-]+)/(\d[\w.+-]*)", server)
        if pm:
            result["product"] = pm.group(1)
            result["version"] = pm.group(2)
        else:
            result["product"] = server.split(" ")[0]
        return result

    match = _SMTP_PRODUCT_RE.search(text)
    if match:
        result["product"] = match.group(1)
        return result

    match = _PRODUCT_SLASH_VERSION_RE.search(text)
    if match:
        result["product"] = match.group(1).strip()
        result["version"] = match.group(2)
        return result

    match = _BARE_VERSION_RE.search(text)
    if match and len(text) < 80:
        result["version"] = match.group(0)

    return result


def categorize_service(normalized_name: Optional[str]) -> Optional[str]:
    if not normalized_name:
        return None
    return CATEGORY_MAP.get(normalized_name, "Other")


def calculate_confidence(
    normalized_name: Optional[str],
    normalized_product: Optional[str],
    version: Optional[str],
) -> int:
    if normalized_name and normalized_product and version:
        return 98
    if normalized_name and normalized_product:
        return 92
    if normalized_name:
        return 85
    if normalized_product:
        return 70
    if version:
        return 60
    return 30


def generate_notes(
    original_name: Optional[str],
    original_product: Optional[str],
    original_version: Optional[str],
    normalized_name: Optional[str],
    normalized_product: Optional[str],
    os_from_version: Optional[str],
) -> Optional[str]:
    notes_parts = []
    if original_name and normalized_name and original_name != normalized_name:
        notes_parts.append(f"Normalized from '{original_name}' to '{normalized_name}'")
    if original_product and normalized_product and original_product != normalized_product:
        notes_parts.append(f"Product normalized from '{original_product}' to '{normalized_product}'")
    if os_from_version and original_version:
        notes_parts.append(f"OS detected from version string: {os_from_version}")
    if not notes_parts:
        return None
    return "; ".join(notes_parts)


def enrich_service(service: Service) -> Service:
    normalized_name = normalize_service_name(service.name)
    normalized_product = normalize_product(service.product)
    normalized_version = extract_normalized_version(service.version)
    category = categorize_service(normalized_name)
    os_from_version = extract_os_from_version(service.version)
    banner_info = analyze_banner(service.banner)

    banner_product = normalize_product(banner_info.get("product")) or banner_info.get("product")
    banner_version = banner_info.get("version")
    product_from_banner = banner_product and not normalized_product
    version_from_banner = banner_version and not normalized_version
    if banner_product and not normalized_product:
        normalized_product = banner_product
    if banner_version and not normalized_version:
        normalized_version = extract_normalized_version(banner_version)
    if banner_info.get("os") and not os_from_version:
        os_from_version = banner_info["os"]

    confidence = calculate_confidence(normalized_name, normalized_product, normalized_version or service.version)
    notes = generate_notes(
        original_name=service.name,
        original_product=service.product,
        original_version=service.version,
        normalized_name=normalized_name,
        normalized_product=normalized_product,
        os_from_version=os_from_version,
    )

    notes_parts = list(notes.split("; ")) if notes else []
    if banner_info.get("protocol") and service.banner:
        notes_parts.append(f"Banner protocol detected: {banner_info['protocol']}")
    if product_from_banner or version_from_banner:
        derived = " ".join(
            part
            for part in (banner_product or banner_info.get("product"), banner_version)
            if part
        )
        if derived:
            notes_parts.append(f"Banner fingerprint: {derived}")
    notes = "; ".join(notes_parts) or None

    service.normalized_name = normalized_name
    service.normalized_product = normalized_product
    service.normalized_version = normalized_version
    service.category = category
    service.confidence = confidence
    service.notes = notes

    return service


async def service_intelligence_handler(
    assessment_id: str,
    target: str,
    parameters: Optional[dict] = None,
    tracker: Optional[ProgressTracker] = None,
) -> dict:
    logger.info(
        "Service intelligence handler invoked: assessment={id}, target={target}",
        id=assessment_id,
        target=target,
    )

    start_time = datetime.now(timezone.utc)
    artifact_dir = artifact_manager.create_stage_directory(
        assessment_id, "service_intelligence"
    )

    command_str = f"service_intelligence assessment={assessment_id} target={target}"
    artifact_manager.save_command(artifact_dir, command_str)

    metadata = {
        "assessment_id": assessment_id,
        "stage": "service_intelligence",
        "target": target,
        "parameters": parameters or {},
        "start_time": start_time.isoformat(),
    }
    artifact_manager.save_metadata(artifact_dir, metadata)

    if tracker:
        tracker.update_stage_status("service_intelligence", StageStatus.RUNNING)
        tracker.update_stage_progress("service_intelligence", 5.0)

    if tracker:
        tracker.update_stage_progress("service_intelligence", 10.0)

    async with async_session_factory() as session:
        services_result = await session.execute(
            select(Service)
            .join(Port, Service.port_id == Port.id)
            .join(Host, Port.host_id == Host.id)
            .where(Host.scan_id == uuid.UUID(assessment_id))
        )
        services = list(services_result.scalars().all())

    if not services:
        logger.warning("No services found for assessment {id}", id=assessment_id)
        end_time = datetime.now(timezone.utc)
        artifact_manager.save_json(artifact_dir, {
            "status": "no_services",
            "total_services": 0,
            "total_enriched": 0,
        })
        async with async_session_factory() as session:
            await artifact_manager.store_metadata(
                session=session,
                assessment_id=assessment_id,
                stage_name="service_intelligence",
                artifact_dir=artifact_dir,
                status="completed",
                scanner_name="service_intelligence",
                command=command_str,
                parameters=parameters or {},
                target=target,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                output_type="json",
            )
            await session.commit()
        if tracker:
            tracker.update_stage_progress("service_intelligence", 100.0)
            tracker.update_stage_status("service_intelligence", StageStatus.COMPLETED)
        return {"success": True, "summary": {"total_services": 0, "total_enriched": 0}}

    total = len(services)
    enriched_count = 0
    categories_found = {}
    confidence_distribution = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    enriched_services_data = []

    progress_per_service = 80.0 / total if total > 0 else 0

    async with async_session_factory() as session:
        for idx, service in enumerate(services):
            try:
                enrich_service(service)
                session.add(service)
                enriched_count += 1

                enriched_services_data.append({
                    "id": str(service.id),
                    "name": service.name,
                    "normalized_name": service.normalized_name,
                    "product": service.product,
                    "normalized_product": service.normalized_product,
                    "version": service.version,
                    "normalized_version": service.normalized_version,
                    "category": service.category,
                    "confidence": service.confidence,
                    "notes": service.notes,
                })

                if service.category:
                    categories_found[service.category] = categories_found.get(service.category, 0) + 1

                if service.confidence is not None:
                    if service.confidence >= 90:
                        confidence_distribution["high"] += 1
                    elif service.confidence >= 70:
                        confidence_distribution["medium"] += 1
                    elif service.confidence >= 50:
                        confidence_distribution["low"] += 1
                    else:
                        confidence_distribution["unknown"] += 1

                if tracker:
                    progress = 15.0 + ((idx + 1) * progress_per_service)
                    tracker.update_stage_progress("service_intelligence", min(progress, 95.0))

            except Exception as e:
                logger.error("Failed to enrich service {id}: {error}", id=service.id, error=str(e))
                continue

        await session.commit()

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

    results_json = {
        "status": "completed",
        "total_services": total,
        "total_enriched": enriched_count,
        "categories": categories_found,
        "confidence_distribution": confidence_distribution,
        "services": enriched_services_data,
    }
    artifact_manager.save_json(artifact_dir, results_json)

    async with async_session_factory() as session:
        await artifact_manager.store_metadata(
            session=session,
            assessment_id=assessment_id,
            stage_name="service_intelligence",
            artifact_dir=artifact_dir,
            status="completed",
            scanner_name="service_intelligence",
            command=command_str,
            parameters=parameters or {},
            target=target,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            output_type="json",
        )
        await session.commit()

    if tracker:
        tracker.update_stage_progress("service_intelligence", 100.0)
        tracker.update_stage_status("service_intelligence", StageStatus.COMPLETED)

    summary = {
        "total_services": total,
        "total_enriched": enriched_count,
        "categories": categories_found,
        "confidence_distribution": confidence_distribution,
    }

    logger.info(
        "Service intelligence completed: {enriched}/{total} services enriched",
        enriched=enriched_count,
        total=total,
    )

    return {"success": True, "summary": summary}


async def get_services_by_host(
    session: AsyncSession,
    host_id: str,
) -> list[Service]:
    result = await session.execute(
        select(Service)
        .join(Port)
        .where(Port.host_id == uuid.UUID(host_id))
        .options(joinedload(Service.port))
        .order_by(Service.name)
    )
    return list(result.scalars().all())


async def get_services_by_assessment(
    session: AsyncSession,
    assessment_id: str,
) -> list[Service]:
    result = await session.execute(
        select(Service)
        .join(Port, Service.port_id == Port.id)
        .join(Host, Port.host_id == Host.id)
        .where(Host.scan_id == uuid.UUID(assessment_id))
        .options(joinedload(Service.port).joinedload(Port.host))
        .order_by(Service.name)
    )
    return list(result.scalars().all())


async def get_all_services(
    session: AsyncSession,
    page: int = 1,
    per_page: int = 20,
    category: Optional[str] = None,
    confidence_min: Optional[int] = None,
    search: Optional[str] = None,
    sort_by: str = "name",
    sort_order: str = "asc",
    assessment_id: Optional[str] = None,
) -> tuple[list[Service], int]:
    query = select(Service).options(joinedload(Service.port).joinedload(Port.host))
    count_query = select(Service.id).select_from(Service)

    if assessment_id:
        try:
            aid = uuid.UUID(assessment_id)
        except ValueError:
            return [], 0
        query = query.join(Port, Service.port_id == Port.id).join(Host, Port.host_id == Host.id)
        query = query.where(Host.scan_id == aid)
        count_query = (
            count_query.join(Port, Service.port_id == Port.id)
            .join(Host, Port.host_id == Host.id)
            .where(Host.scan_id == aid)
        )

    if category:
        query = query.where(Service.category == category)
        count_query = count_query.where(Service.category == category)
    if confidence_min is not None:
        query = query.where(Service.confidence >= confidence_min)
        count_query = count_query.where(Service.confidence >= confidence_min)
    if search:
        query = query.where(
            Service.name.ilike(f"%{search}%")
            | Service.product.ilike(f"%{search}%")
            | Service.normalized_name.ilike(f"%{search}%")
            | Service.normalized_product.ilike(f"%{search}%")
            | Service.version.ilike(f"%{search}%")
        )
        count_query = count_query.where(
            Service.name.ilike(f"%{search}%")
            | Service.product.ilike(f"%{search}%")
            | Service.normalized_name.ilike(f"%{search}%")
            | Service.normalized_product.ilike(f"%{search}%")
            | Service.version.ilike(f"%{search}%")
        )

    total_result = await session.execute(count_query)
    total = len(total_result.fetchall())

    sort_column = getattr(Service, sort_by, Service.name)
    if sort_order == "desc":
        sort_column = sort_column.desc()
    query = query.order_by(sort_column).offset((page - 1) * per_page).limit(per_page)

    result = await session.execute(query)
    services = list(result.scalars().all())

    return services, total


async def get_service_by_id(
    session: AsyncSession,
    service_id: str,
) -> Optional[Service]:
    try:
        uid = uuid.UUID(service_id)
    except ValueError:
        return None
    result = await session.execute(
        select(Service)
        .where(Service.id == uid)
        .options(joinedload(Service.port).joinedload(Port.host))
    )
    return result.scalar_one_or_none()


async def get_all_categories(
    session: AsyncSession,
    assessment_id: Optional[str] = None,
) -> list[str]:
    query = select(Service.category).where(Service.category.isnot(None))
    if assessment_id:
        try:
            aid = uuid.UUID(assessment_id)
        except ValueError:
            return []
        query = (
            query.join(Port, Service.port_id == Port.id)
            .join(Host, Port.host_id == Host.id)
            .where(Host.scan_id == aid)
        )
    query = query.distinct().order_by(Service.category)
    result = await session.execute(query)
    return [row[0] for row in result.fetchall()]
