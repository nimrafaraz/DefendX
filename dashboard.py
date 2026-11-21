"""Central dashboard (FR-12)."""
import plotly.graph_objects as go
import streamlit as st

from .. import auth, config, events, intel, services
from ..ui import components as ui


def render(user: dict) -> None:
    if not ui.require_permission(user, "view_dashboard"):
        return
    st.title("Operations Dashboard")
    ui.banner()

    evs = events.list_events(limit=5000)
    score = intel.overall_score(evs)
    level = intel.risk_level(score)
    live = intel.unresolved(evs)
    incidents = intel.correlate(evs, config.DEFAULT_CORRELATION_MINUTES)
    active = intel.active_incidents(incidents)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        ui.metric_card("Threat level", level, f"risk score {score} / 100", ui.TONE_FOR_LEVEL[level])
    with c2:
        ui.metric_card("Unresolved events", len(live), f"of {len(evs)} total")
    with c3:
        crit = sum(1 for e in live if e["severity"] == "CRITICAL")
        ui.metric_card("Critical", crit, "unresolved", "bad" if crit else "ok")
    with c4:
        ui.metric_card("Active incidents", len(active), "multi-domain", "warn" if active else "ok")

    if auth.has_permission(user["role"], "run_simulations"):
        if st.button("Inject demo scenario (RF + cyber + radar)"):
            services.inject_scenario(user)
            st.success("Scenario injected. Open the Intelligence page to see the correlated incident.")
            st.rerun()

    st.subheader("Domain status")
    cols = st.columns(3)
    names = {"RF": "Electronic Activity", "CYBER": "Cyber Defence", "RADAR": "Radar"}
    tone = {"NOMINAL": "ok", "ACTIVE": "neutral", "ELEVATED": "warn", "ALERT": "bad"}
    for col, (domain, info) in zip(cols, intel.domain_status(evs).items()):
        with col:
            ui.metric_card(names[domain], info["status"],
                           f"{info['unresolved']} unresolved, highest risk {info['max_risk']:.0f}",
                           tone[info["status"]])

    left, right = st.columns([2, 1])
    with left:
        hourly = intel.events_per_hour(evs)
        fig = go.Figure()
        for domain in config.DOMAINS:
            d = hourly[hourly["domain"] == domain]
            fig.add_bar(x=d["hour"], y=d["count"], name=domain, marker_color=ui.DOMAIN_COLOR[domain])
        fig.update_layout(barmode="stack", title="Events per hour by domain")
        st.plotly_chart(ui.style_fig(fig, 320), key="dash_hourly")
    with right:
        sev_counts = [sum(1 for e in evs if e["severity"] == s) for s in config.SEVERITIES]
        fig = go.Figure(go.Pie(labels=list(config.SEVERITIES), values=sev_counts, hole=0.55,
                               marker=dict(colors=[ui.SEVERITY_COLOR[s] for s in config.SEVERITIES])))
        fig.update_layout(title="Severity mix")
        st.plotly_chart(ui.style_fig(fig, 320), key="dash_severity")

    st.subheader("Latest unresolved alerts")
    latest = intel.unresolved(evs)[:10]
    if latest:
        st.dataframe(ui.events_dataframe(latest), hide_index=True)
    else:
        st.success("No unresolved alerts.")

    st.subheader("Strongest correlated incidents")
    top = intel.strongest(incidents, 5)
    if not top:
        st.info("No cross-domain incidents yet.")
    for inc in top:
        st.markdown(f"**{inc['id']}** &nbsp; {ui.level_badge(inc['level'])} &nbsp; score {inc['score']} "
                    f"&mdash; {' + '.join(inc['domains'])}, {len(inc['events'])} events, "
                    f"{inc['start'][:16].replace('T', ' ')} UTC"
                    f"{'' if inc['active'] else ' (resolved)'}", unsafe_allow_html=True)
