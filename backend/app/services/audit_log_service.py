"""Audit log querying for the Audit Log Viewer.

Read-only helpers used by the /audit-logs API. The audit recording
implementation (AuditLog model, AuthService.log_audit, call sites) is not
touched here; this module only builds queries and serializes records.
"""

import csv
import io
import json
from datetime import UTC, date, datetime, time

from sqlalchemy import String, cast, func, not_, or_, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.audit_log import AuditLog
from app.models.user import User

VALID_SORT_FIELDS = {"timestamp", "action", "username"}
VALID_STATUSES = {"success", "failure"}

_FAILURE_STATUS_VALUES = {"failure", "error", "failed", "denied"}


def audit_status(details: dict | None) -> str:
    """Derive a success/failure status from an audit record's details.

    The platform records successful operations by default; records carry a
    failure marker in their details JSON when an operation was rejected
    (e.g. ``{"status": "failure"}`` or ``{"success": false}``).
    """
    if not isinstance(details, dict):
        return "success"
    raw = details.get("status")
    if isinstance(raw, str) and raw.lower() in _FAILURE_STATUS_VALUES:
        return "failure"
    if isinstance(raw, str) and raw.lower() in ("success", "ok"):
        return "success"
    if details.get("success") is False:
        return "failure"
    outcome = details.get("outcome")
    if isinstance(outcome, str) and outcome.lower() in _FAILURE_STATUS_VALUES:
        return "failure"
    return "success"


def _status_condition(status: str | None):
    """SQLAlchemy condition matching records with the given derived status."""
    details = cast(AuditLog.details, JSONB)
    failure = or_(
        details.op("->>")("status").in_(list(_FAILURE_STATUS_VALUES)),
        details.op("->>")("success") == "false",
        details.op("->>")("outcome").in_(list(_FAILURE_STATUS_VALUES)),
    )
    if status == "failure":
        return failure
    if status == "success":
        return not_(func.coalesce(failure, False))
    return None


def _build_query(
    *,
    search: str | None,
    user: str | None,
    action: str | None,
    date_from: datetime | None,
    date_to: datetime | None,
    status: str | None,
    sort_by: str,
    sort_order: str,
):
    query = (
        select(AuditLog)
        .outerjoin(AuditLog.user)
        .options(selectinload(AuditLog.user))
    )

    if search:
        term = f"%{search.strip()}%"
        search_conditions = [
            User.username.ilike(term),
            User.role.ilike(term),
            User.email.ilike(term),
            AuditLog.action.ilike(term),
            AuditLog.resource_type.ilike(term),
            AuditLog.resource_id.ilike(term),
            AuditLog.ip_address.ilike(term),
            AuditLog.user_agent.ilike(term),
            cast(AuditLog.details, String).ilike(term),
            cast(AuditLog.timestamp, String).ilike(term),
        ]
        search_keyword = search.strip().lower()
        if search_keyword in ("success", "ok"):
            search_conditions.append(_status_condition("success"))
        elif search_keyword in _FAILURE_STATUS_VALUES:
            search_conditions.append(_status_condition("failure"))
        query = query.where(or_(*search_conditions))
    if user:
        query = query.where(User.username.ilike(f"%{user.strip()}%"))
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action.strip()}%"))
    if date_from:
        query = query.where(AuditLog.timestamp >= date_from)
    if date_to:
        query = query.where(AuditLog.timestamp <= date_to)
    status_cond = _status_condition(status)
    if status_cond is not None:
        query = query.where(status_cond)

    if sort_by == "username":
        column = User.username
    elif sort_by == "action":
        column = AuditLog.action
    else:
        column = AuditLog.timestamp
    column = column.desc() if sort_order == "desc" else column.asc()
    query = query.order_by(column, AuditLog.id)

    return query


async def query_audit_logs(
    session: AsyncSession,
    *,
    search: str | None = None,
    user: str | None = None,
    action: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    status: str | None = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
    page: int = 1,
    per_page: int = 20,
) -> tuple[list[AuditLog], int]:
    """Return a page of audit logs plus the total count of matching records."""
    base = _build_query(
        search=search,
        user=user,
        action=action,
        date_from=date_from,
        date_to=date_to,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    total = (
        await session.execute(select(func.count()).select_from(base.subquery()))
    ).scalar_one()
    result = await session.execute(
        base.offset((page - 1) * per_page).limit(per_page)
    )
    return list(result.scalars().all()), total


async def fetch_all_matching(
    session: AsyncSession,
    *,
    search: str | None = None,
    user: str | None = None,
    action: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    status: str | None = None,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
) -> list[AuditLog]:
    """Return every matching audit log (used by CSV/JSON export)."""
    query = _build_query(
        search=search,
        user=user,
        action=action,
        date_from=date_from,
        date_to=date_to,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    result = await session.execute(query)
    return list(result.scalars().all())


def audit_log_to_dict(log: AuditLog) -> dict:
    return {
        "id": str(log.id),
        "user_id": str(log.user_id) if log.user_id else None,
        "username": log.user.username if log.user else None,
        "action": log.action,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "details": log.details,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        "status": audit_status(log.details),
    }


async def list_audit_users(session: AsyncSession) -> list[str]:
    """Distinct usernames that have audit records."""
    with_audits = select(AuditLog.user_id).where(AuditLog.user_id.is_not(None))
    result = await session.execute(
        select(User.username)
        .where(User.id.in_(with_audits))
        .order_by(User.username)
    )
    return [row[0] for row in result.all()]


async def list_audit_actions(session: AsyncSession) -> list[str]:
    result = await session.execute(
        select(AuditLog.action)
        .distinct()
        .order_by(AuditLog.action)
    )
    return [row[0] for row in result.all()]


def render_csv(logs: list[AuditLog]) -> str:
    """Render audit logs as CSV (with a UTF-8 BOM for Excel friendliness)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["timestamp", "user", "action", "target_type", "target_id",
         "ip_address", "status", "user_agent", "details"]
    )
    for log in logs:
        writer.writerow([
            log.timestamp.isoformat() if log.timestamp else "",
            log.user.username if log.user else "",
            log.action,
            log.resource_type or "",
            log.resource_id or "",
            log.ip_address or "",
            audit_status(log.details),
            log.user_agent or "",
            json.dumps(log.details) if log.details else "",
        ])
    return "\ufeff" + buffer.getvalue()


def day_boundaries(
    date_from: date | None, date_to: date | None
) -> tuple[datetime | None, datetime | None]:
    """Normalize an inclusive date-only range to UTC datetimes."""
    start = None
    end = None
    if date_from:
        start = datetime.combine(date_from, time.min, tzinfo=UTC)
    if date_to:
        end = datetime.combine(date_to, time.max, tzinfo=UTC)
    return start, end
