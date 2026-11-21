"""Central event store: every sensor module writes its alerts here."""
from __future__ import annotations

from . import config, db
from .timeutil import now_iso


def add_event(domain: str, severity: str, title: str, details: str = "", source: str = "",
              risk_score: float | None = None, status: str = "OPEN",
              ts: str | None = None) -> int:
    if domain not in config.DOMAINS:
        raise ValueError(f"Unknown domain: {domain}")
    if severity not in config.SEVERITIES:
        raise ValueError(f"Unknown severity: {severity}")
    if status not in config.STATUSES:
        raise ValueError(f"Unknown status: {status}")
    if not title.strip():
        raise ValueError("Event title is empty.")
    if risk_score is None:
        risk_score = config.SEVERITY_RISK[severity]
    risk_score = max(0.0, min(100.0, float(risk_score)))
    return db.execute(
        "INSERT INTO events (ts, domain, severity, title, details, source, status, risk_score) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (ts or now_iso(), domain, severity, title.strip(), details, source, status, risk_score),
    )


def get_event(event_id: int) -> dict | None:
    return db.query_one("SELECT * FROM events WHERE id = ?", (event_id,))


def list_events(domain: str | None = None, status: str | None = None,
                unresolved_only: bool = False, since: str | None = None,
                limit: int | None = 500, newest_first: bool = True) -> list[dict]:
    sql, params, where = "SELECT * FROM events", [], []
    if domain:
        where.append("domain = ?"); params.append(domain)
    if status:
        where.append("status = ?"); params.append(status)
    if unresolved_only:
        where.append("status != 'RESOLVED'")
    if since:
        where.append("ts >= ?"); params.append(since)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts " + ("DESC" if newest_first else "ASC") + ", id " + \
           ("DESC" if newest_first else "ASC")
    if limit:
        sql += " LIMIT ?"; params.append(limit)
    return db.query(sql, params)


def set_status(event_id: int, status: str) -> None:
    if status not in config.STATUSES:
        raise ValueError(f"Unknown status: {status}")
    if not get_event(event_id):
        raise ValueError("Event not found.")
    db.execute("UPDATE events SET status = ? WHERE id = ?", (status, event_id))


def count_events(domain: str | None = None, unresolved_only: bool = False) -> int:
    sql, params, where = "SELECT COUNT(*) AS n FROM events", [], []
    if domain:
        where.append("domain = ?"); params.append(domain)
    if unresolved_only:
        where.append("status != 'RESOLVED'")
    if where:
        sql += " WHERE " + " AND ".join(where)
    return db.query_one(sql, params)["n"]


def clear_events() -> None:
    db.execute("DELETE FROM events")
