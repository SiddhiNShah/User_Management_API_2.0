"""Audit logging for admin actions.

Appends an AuditLog row within the caller's DB session, so the audit entry
commits atomically with the action it describes. Never log secrets.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditAction, AuditLog, User

# Fields that must never appear in audit payloads.
_FORBIDDEN_KEYS = {"password", "new_password", "current_password", "password_hash", "token"}


def _safe_details(details: dict[str, Any] | None) -> str | None:
    if not details:
        return None
    clean = {k: v for k, v in details.items() if k not in _FORBIDDEN_KEYS}
    # default=str handles enums, dates, datetimes.
    return json.dumps(clean, default=str, sort_keys=True)


def record(
    db: Session,
    *,
    actor: User,
    action: AuditAction,
    target: User | None,
    details: dict[str, Any] | None = None,
) -> None:
    # Caller owns the commit; we just add the row to the session.
    entry = AuditLog(
        actor_user_id=actor.user_id,
        target_user_id=target.user_id if target else None,
        action=action,
        details=_safe_details(details),
    )
    db.add(entry)
