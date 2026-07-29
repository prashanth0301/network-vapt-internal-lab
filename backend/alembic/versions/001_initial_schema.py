"""Initial database schema

Revision ID: 001
Revises:
Create Date: 2026-07-28
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "hosts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("mac_address", sa.String(), nullable=True),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("os_name", sa.String(255), nullable=True),
        sa.Column("os_version", sa.String(255), nullable=True),
        sa.Column("os_accuracy", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(20), server_default="unknown"),
        sa.Column("latency", sa.Float(), nullable=True),
        sa.Column("is_alive", sa.Boolean(), server_default="false"),
        sa.Column("first_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_hosts_ip", "hosts", ["ip_address"])
    op.create_index("idx_hosts_status", "hosts", ["status"])
    op.create_index("idx_hosts_scan_id", "hosts", ["scan_id"])

    op.create_table(
        "ports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(10), server_default="tcp"),
        sa.Column("state", sa.String(20), server_default="unknown"),
        sa.Column("reason", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("host_id", "port", "protocol", name="uq_host_port_protocol"),
    )
    op.create_index("idx_ports_host_id", "ports", ["host_id"])
    op.create_index("idx_ports_state", "ports", ["state"])

    op.create_table(
        "services",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("port_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=True),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column("version", sa.String(255), nullable=True),
        sa.Column("extra_info", sa.Text(), nullable=True),
        sa.Column("tunnel", sa.String(50), nullable=True),
        sa.Column("protocol", sa.String(50), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_services_port_id", "services", ["port_id"])
    op.create_index("idx_services_name", "services", ["name"])

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scan_type", sa.String(50), nullable=False),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("parameters", postgresql.JSONB(), nullable=True),
        sa.Column("summary", postgresql.JSONB(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_scans_type", "scans", ["scan_type"])
    op.create_index("idx_scans_status", "scans", ["status"])

    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("port_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("ports.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("solution", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("cvss_vector", sa.String(100), nullable=True),
        sa.Column("cve_ids", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("plugin_id", sa.String(100), nullable=True),
        sa.Column("plugin_output", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_vulns_host_id", "vulnerabilities", ["host_id"])
    op.create_index("idx_vulns_severity", "vulnerabilities", ["severity"])

    op.create_table(
        "cves",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("vuln_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True),
        sa.Column("cve_id", sa.String(20), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(100), nullable=True),
        sa.Column("cvss_severity", sa.String(20), nullable=True),
        sa.Column("cwe_id", sa.String(50), nullable=True),
        sa.Column("exploit_available", sa.Boolean(), server_default="false"),
        sa.Column("metasploit_module", sa.String(500), nullable=True),
        sa.Column("reference_urls", postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column("published_date", sa.Date(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_cves_cve_id", "cves", ["cve_id"])
    op.create_index("idx_cves_msf_module", "cves", ["metasploit_module"])

    op.create_table(
        "exploits",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cve_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("cves.id", ondelete="SET NULL"), nullable=True),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("module_name", sa.String(500), nullable=False),
        sa.Column("module_type", sa.String(50), nullable=True),
        sa.Column("target", sa.String(255), nullable=True),
        sa.Column("rank", sa.String(50), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("payloads", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_exploits_host_id", "exploits", ["host_id"])

    op.create_table(
        "exploit_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("exploit_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("exploits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("session_id", sa.String(100), nullable=True),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_exploit_runs_exploit_id", "exploit_runs", ["exploit_id"])
    op.create_index("idx_exploit_runs_host_id", "exploit_runs", ["host_id"])
    op.create_index("idx_exploit_runs_status", "exploit_runs", ["status"])

    op.create_table(
        "packet_captures",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("filepath", sa.Text(), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=True),
        sa.Column("packet_count", sa.Integer(), nullable=True),
        sa.Column("filter", sa.String(500), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column("protocol_stats", postgresql.JSONB(), nullable=True),
        sa.Column("capture_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("capture_ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("report_type", sa.String(20), nullable=False),
        sa.Column("format", sa.String(10), nullable=False),
        sa.Column("filepath", sa.Text(), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=True),
        sa.Column("include_exec_summary", sa.Boolean(), server_default="true"),
        sa.Column("include_technical", sa.Boolean(), server_default="true"),
        sa.Column("include_recommendations", sa.Boolean(), server_default="true"),
        sa.Column("generated_by", sa.String(255), server_default="system"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_reports_scan_id", "reports", ["scan_id"])

    op.create_table(
        "logs",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("level", sa.String(20), nullable=False),
        sa.Column("module", sa.String(100), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_logs_level_module", "logs", ["level", "module"])
    op.create_index("idx_logs_created", "logs", ["created_at"])

    op.create_table(
        "settings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.String(255), nullable=False, unique=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("category", sa.String(100), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_settings_key", "settings", ["key"])


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_table("logs")
    op.drop_table("reports")
    op.drop_table("packet_captures")
    op.drop_table("exploit_runs")
    op.drop_table("exploits")
    op.drop_table("cves")
    op.drop_table("vulnerabilities")
    op.drop_table("scans")
    op.drop_table("services")
    op.drop_table("ports")
    op.drop_table("hosts")
