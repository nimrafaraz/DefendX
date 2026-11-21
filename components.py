"""Shared widgets: cards, badges, event table with actions, chart styling."""
from __future__ import annotations

import html

import pandas as pd
import streamlit as st

from .. import auth, services

SEVERITY_ICON = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
SEVERITY_COLOR = {"LOW": "#5fe08a", "MEDIUM": "#f5d24a", "HIGH": "#ff9b4a", "CRITICAL": "#ff6b6b"}
DOMAIN_COLOR = {"RF": "#4aa8ff", "CYBER": "#b07cff", "RADAR": "#19c3a6"}
TONE_FOR_LEVEL = {"LOW": "ok", "MEDIUM": "warn", "HIGH": "bad", "CRITICAL": "bad"}


def banner(text: str = "Synthetic data only. Educational simulation: nothing here touches a real radio, "
                       "network or radar.") -> None:
    st.markdown(f'<div class="dx-banner">{html.escape(text)}</div>', unsafe_allow_html=True)


def metric_card(label: str, value, sub: str = "", tone: str = "neutral") -> None:
    st.markdown(
        f'<div class="dx-card"><div class="dx-label">{html.escape(str(label))}</div>'
        f'<div class="dx-value dx-{tone}">{html.escape(str(value))}</div>'
        f'<div class="dx-sub">{html.escape(str(sub))}</div></div>', unsafe_allow_html=True)


def level_badge(level: str) -> str:
    return f'<span class="dx-badge dx-{level}">{html.escape(level)}</span>'


def style_fig(fig, height: int = 360):
    fig.update_layout(template="plotly_dark", height=height, margin=dict(l=10, r=10, t=40, b=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    return fig


def require_permission(user: dict, permission: str) -> bool:
    """Page-level guard (defence in depth: app.py also hides pages the role cannot use)."""
    if auth.has_permission(user["role"], permission):
        return True
    st.error("Your role does not have access to this page.")
    return False


def events_dataframe(evs: list[dict]) -> pd.DataFrame:
    rows = [{"ID": e["id"], "Time (UTC)": e["ts"][:19].replace("T", " "), "Domain": e["domain"],
             "Severity": f"{SEVERITY_ICON[e['severity']]} {e['severity']}", "Title": e["title"],
             "Status": e["status"], "Risk": round(e["risk_score"])} for e in evs]
    return pd.DataFrame(rows, columns=["ID", "Time (UTC)", "Domain", "Severity", "Title", "Status", "Risk"])


def event_table(evs: list[dict], user: dict, key: str, max_rows: int = 100) -> None:
    """Show events, plus acknowledge/resolve controls for roles that may manage events."""
    if not evs:
        st.info("No events recorded yet.")
        return
    st.dataframe(events_dataframe(evs[:max_rows]), hide_index=True)
    if not auth.has_permission(user["role"], "manage_events"):
        return
    open_events = [e for e in evs if e["status"] != "RESOLVED"][:max_rows]
    if not open_events:
        return
    c1, c2, c3 = st.columns([3, 1, 1])
    chosen = c1.selectbox("Event to update", [e["id"] for e in open_events], key=f"{key}_pick",
                          format_func=lambda i: next(f"#{e['id']}  {e['title']}  [{e['status']}]"
                                                     for e in open_events if e["id"] == i))
    if c2.button("Acknowledge", key=f"{key}_ack"):
        services.acknowledge_event(user, chosen)
        st.rerun()
    if c3.button("Resolve", key=f"{key}_res"):
        services.resolve_event(user, chosen)
        st.rerun()
