"""Append-only security audit trail."""
from __future__ import annotations

from . import db
from .timeutil import now_iso


def log(user_id: int | None, action: str, detail: str = "") -> int:
    return db.execute(
        "INSERT INTO audit_log (ts, user_id, action, detail) VALUES (?,?,?,?)",
        (now_iso(), user_id, action, detail[:500]),
    )


def recent(limit: int = 300, action: str | None = None) -> list[dict]:
    sql = (
        "SELECT a.id, a.ts, a.user_id, COALESCE(u.username, '-') AS username, "
        "a.action, a.detail FROM audit_log a LEFT JOIN users u ON u.id = a.user_id"
    )
    params: list = []
    if action:
        sql += " WHERE a.action = ?"
        params.append(action)
    sql += " ORDER BY a.id DESC LIMIT ?"
    params.append(limit)
    return db.query(sql, params)
