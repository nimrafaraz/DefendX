"""UTC time helpers. All timestamps in DEFEND-X are UTC ISO-8601 text."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def from_iso(text: str) -> datetime:
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def now_iso() -> str:
    return to_iso(utcnow())


__all__ = ["utcnow", "to_iso", "from_iso", "now_iso", "timedelta"]
