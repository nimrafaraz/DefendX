"""Intelligence analysis: risk scoring, cross-domain correlation and reports."""
from __future__ import annotations

import html
from datetime import timedelta

import pandas as pd

from . import config
from .timeutil import from_iso, to_iso, utcnow


# ---------------------------------------------------------------- scoring
def risk_level(score: float) -> str:
    for bound, name in config.LEVEL_BOUNDS:
        if score < bound:
            return name
    return "CRITICAL"


def unresolved(events: list[dict]) -> list[dict]:
    return [e for e in events if e["status"] != "RESOLVED"]


def overall_score(events: list[dict]) -> float:
    """0.6 x highest unresolved risk + 0.4 x mean of top five, + 6 per extra serious
    domain, + up to 5 for volume, capped at 100."""
    live = unresolved(events)
    if not live:
        return 0.0
    risks = sorted((e["risk_score"] for e in live), reverse=True)
    score = 0.6 * risks[0] + 0.4 * (sum(risks[:5]) / len(risks[:5]))
    serious_domains = {e["domain"] for e in live if e["risk_score"] >= config.SERIOUS_RISK}
    score += config.EXTRA_DOMAIN_POINTS * max(0, len(serious_domains) - 1)
    score += min(config.VOLUME_MAX_POINTS, config.VOLUME_MAX_POINTS * len(live) / config.VOLUME_FULL_AT)
    return round(min(100.0, score), 1)


# ------------------------------------------------------------ correlation
def correlate(events: list[dict], window_minutes: int = config.DEFAULT_CORRELATION_MINUTES) -> list[dict]:
    """Start a window at each event, group everything inside it, and keep groups that
    span two or more domains (dropping groups contained in an earlier kept one)."""
    ordered = sorted(events, key=lambda e: (e["ts"], e["id"]))
    times = [from_iso(e["ts"]) for e in ordered]
    window = timedelta(minutes=window_minutes)
    kept: list[frozenset] = []
    groups: list[list[dict]] = []
    for i, start in enumerate(times):
        members = [ordered[j] for j in range(i, len(ordered)) if times[j] - start <= window]
        ids = frozenset(e["id"] for e in members)
        if len({e["domain"] for e in members}) < 2:
            continue
        if any(ids <= k for k in kept):
            continue
        kept.append(ids)
        groups.append(members)

    incidents = []
    for n, members in enumerate(groups, start=1):
        domains = sorted({e["domain"] for e in members})
        risks = [e["risk_score"] for e in members]
        score = 0.6 * max(risks) + 0.4 * (sum(risks) / len(risks)) \
            + config.CROSS_DOMAIN_BONUS * (len(domains) - 1)
        score = round(min(100.0, score), 1)
        incidents.append({
            "id": f"INC-{n:03d}", "start": members[0]["ts"], "end": members[-1]["ts"],
            "domains": domains, "events": members, "event_ids": [e["id"] for e in members],
            "score": score, "level": risk_level(score),
            "active": any(e["status"] != "RESOLVED" for e in members),
            "title": "Multi-domain activity: " + " + ".join(domains)})
    return incidents


def active_incidents(incidents: list[dict]) -> list[dict]:
    return [i for i in incidents if i["active"]]


def strongest(incidents: list[dict], n: int = 5) -> list[dict]:
    return sorted(incidents, key=lambda i: i["score"], reverse=True)[:n]


# ----------------------------------------------------------- chart helpers
def events_frame(events: list[dict]) -> pd.DataFrame:
    cols = ["id", "ts", "time", "domain", "severity", "title", "status", "risk_score"]
    if not events:
        return pd.DataFrame(columns=cols)
    df = pd.DataFrame(events)
    df["time"] = pd.to_datetime(df["ts"], utc=True)
    return df


def events_per_hour(events: list[dict]) -> pd.DataFrame:
    df = events_frame(events)
    if df.empty:
        return pd.DataFrame(columns=["hour", "domain", "count"])
    df["hour"] = df["time"].dt.floor("h")
    return df.groupby(["hour", "domain"]).size().reset_index(name="count")


def risk_trend(events: list[dict]) -> pd.DataFrame:
    """Highest risk score per hour (all events), for the trend line."""
    df = events_frame(events)
    if df.empty:
        return pd.DataFrame(columns=["hour", "max_risk"])
    df["hour"] = df["time"].dt.floor("h")
    return df.groupby("hour")["risk_score"].max().reset_index(name="max_risk")


def severity_matrix(events: list[dict]) -> pd.DataFrame:
    """Domains (rows) x severities (columns) of unresolved events."""
    matrix = pd.DataFrame(0, index=list(config.DOMAINS), columns=list(config.SEVERITIES))
    for e in unresolved(events):
        matrix.loc[e["domain"], e["severity"]] += 1
    return matrix


def domain_status(events: list[dict]) -> dict[str, dict]:
    """Per-domain card data: status word, unresolved count, highest risk."""
    out = {}
    for d in config.DOMAINS:
        live = [e for e in unresolved(events) if e["domain"] == d]
        top = max((e["risk_score"] for e in live), default=0.0)
        out[d] = {"unresolved": len(live), "max_risk": top,
                  "status": "ALERT" if top >= 70 else "ELEVATED" if top >= config.SERIOUS_RISK
                  else "ACTIVE" if live else "NOMINAL"}
    return out


# ----------------------------------------------------------------- reports
def _recommendations(level: str) -> list[str]:
    base = {
        "LOW": ["Continue routine monitoring.", "Review and close resolved items."],
        "MEDIUM": ["Review open events and acknowledge those understood.",
                   "Check the authorised-emitter plan and network baselines."],
        "HIGH": ["Prioritise the highest-risk open events and the active incidents.",
                 "Assign an owner to each active incident and record the outcome."],
        "CRITICAL": ["Escalate to the duty supervisor and treat active incidents as urgent.",
                     "Hold regular status updates until the score returns to HIGH or lower."],
    }
    return base[level] + ["This is a synthetic training exercise: no real systems were affected."]


def build_report(events: list[dict], window_minutes: int = config.DEFAULT_CORRELATION_MINUTES,
                 generated_by: str = "system", now=None) -> dict:
    """Build the report as plain data; the Markdown and HTML renderers both use it, so
    every number in a report matches the screen."""
    now = now or utcnow()
    score = overall_score(events)
    level = risk_level(score)
    incidents = correlate(events, window_minutes)
    live = sorted(unresolved(events), key=lambda e: e["risk_score"], reverse=True)
    return {
        "title": "DEFEND-X Intelligence Report", "generated_at": to_iso(now),
        "generated_by": generated_by, "window_minutes": window_minutes,
        "score": score, "level": level,
        "total_events": len(events), "unresolved_events": len(live),
        "by_domain": {d: sum(1 for e in live if e["domain"] == d) for d in config.DOMAINS},
        "by_severity": {s: sum(1 for e in live if e["severity"] == s) for s in config.SEVERITIES},
        "incidents": [{k: i[k] for k in ("id", "title", "start", "end", "domains", "score",
                                         "level", "active")} | {"event_count": len(i["events"])}
                      for i in incidents],
        "top_events": [{k: e[k] for k in ("id", "ts", "domain", "severity", "title", "status",
                                          "risk_score")} for e in live[:10]],
        "recommendations": _recommendations(level),
    }


def render_markdown(r: dict) -> str:
    lines = [f"# {r['title']}", "",
             f"Generated: {r['generated_at']} by {r['generated_by']}  ",
             "Data: synthetic, for education only.", "",
             "## Overall risk", "",
             f"- **Risk score:** {r['score']} / 100", f"- **Level:** {r['level']}",
             f"- Unresolved events: {r['unresolved_events']} of {r['total_events']}",
             "- By domain: " + ", ".join(f"{k} {v}" for k, v in r["by_domain"].items()),
             "- By severity: " + ", ".join(f"{k} {v}" for k, v in r["by_severity"].items()), "",
             f"## Correlated incidents (window {r['window_minutes']} min)", ""]
    if r["incidents"]:
        lines += ["| ID | Domains | Start | Events | Score | Level | Active |", "|---|---|---|---|---|---|---|"]
        lines += [f"| {i['id']} | {' + '.join(i['domains'])} | {i['start']} | {i['event_count']} | "
                  f"{i['score']} | {i['level']} | {'yes' if i['active'] else 'no'} |" for i in r["incidents"]]
    else:
        lines.append("No cross-domain incidents found.")
    lines += ["", "## Highest-risk unresolved events", ""]
    if r["top_events"]:
        lines += ["| ID | Time | Domain | Severity | Title | Status | Risk |", "|---|---|---|---|---|---|---|"]
        lines += [f"| {e['id']} | {e['ts']} | {e['domain']} | {e['severity']} | {e['title']} | "
                  f"{e['status']} | {e['risk_score']:.0f} |" for e in r["top_events"]]
    else:
        lines.append("No unresolved events.")
    lines += ["", "## Recommended actions", ""] + [f"- {x}" for x in r["recommendations"]]
    return "\n".join(lines) + "\n"


def render_html(r: dict) -> str:
    esc = lambda v: html.escape(str(v))  # noqa: E731
    def table(headers, rows):
        head = "".join(f"<th>{esc(h)}</th>" for h in headers)
        body = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in rows)
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    inc = table(["ID", "Domains", "Start", "Events", "Score", "Level", "Active"],
                [(i["id"], " + ".join(i["domains"]), i["start"], i["event_count"], i["score"], i["level"],
                  "yes" if i["active"] else "no") for i in r["incidents"]]) \
        if r["incidents"] else "<p>No cross-domain incidents found.</p>"
    top = table(["ID", "Time", "Domain", "Severity", "Title", "Status", "Risk"],
                [(e["id"], e["ts"], e["domain"], e["severity"], e["title"], e["status"],
                  f"{e['risk_score']:.0f}") for e in r["top_events"]]) \
        if r["top_events"] else "<p>No unresolved events.</p>"
    recs = "".join(f"<li>{esc(x)}</li>" for x in r["recommendations"])
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>{esc(r['title'])}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:900px;margin:2em auto;color:#1b2430}}
table{{border-collapse:collapse;width:100%;margin:1em 0}}th,td{{border:1px solid #ccd;padding:6px 8px;text-align:left}}
th{{background:#eef2f7}}.score{{font-size:1.6em;font-weight:bold}}</style></head><body>
<h1>{esc(r['title'])}</h1><p>Generated {esc(r['generated_at'])} by {esc(r['generated_by'])}. Synthetic data, for education only.</p>
<h2>Overall risk</h2><p class="score">{esc(r['score'])} / 100 &mdash; {esc(r['level'])}</p>
<p>Unresolved events: {esc(r['unresolved_events'])} of {esc(r['total_events'])}.
By domain: {esc(', '.join(f'{k} {v}' for k, v in r['by_domain'].items()))}.
By severity: {esc(', '.join(f'{k} {v}' for k, v in r['by_severity'].items()))}.</p>
<h2>Correlated incidents (window {esc(r['window_minutes'])} min)</h2>{inc}
<h2>Highest-risk unresolved events</h2>{top}
<h2>Recommended actions</h2><ul>{recs}</ul></body></html>"""
