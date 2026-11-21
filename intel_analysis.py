"""Intelligence Analysis page (FR-5, FR-6, FR-7)."""
from datetime import timedelta

import plotly.graph_objects as go
import streamlit as st

from .. import audit, auth, config, events, intel
from ..timeutil import to_iso, utcnow
from ..ui import components as ui


def render(user: dict) -> None:
    if not ui.require_permission(user, "view_intel"):
        return
    st.title("Intelligence Analysis")
    ui.banner()

    c1, c2 = st.columns(2)
    window = c1.slider("Correlation window (minutes)", 1, 60, config.DEFAULT_CORRELATION_MINUTES,
                       key="intel_window")
    lookback = c2.selectbox("Look back", ["6 hours", "24 hours", "48 hours", "All"], index=2,
                            key="intel_lookback")
    since = None if lookback == "All" else to_iso(utcnow() - timedelta(hours=int(lookback.split()[0])))
    evs = events.list_events(since=since, limit=5000)

    score = intel.overall_score(evs)
    level = intel.risk_level(score)
    incidents = intel.correlate(evs, window)

    g, m = st.columns([1, 2])
    with g:
        gauge = go.Figure(go.Indicator(
            mode="gauge+number", value=score, title={"text": f"Overall risk: {level}"},
            gauge={"axis": {"range": [0, 100]}, "bar": {"color": "#e6edf7"},
                   "steps": [{"range": [0, 25], "color": "#14391f"}, {"range": [25, 50], "color": "#3d3410"},
                             {"range": [50, 75], "color": "#44230f"}, {"range": [75, 100], "color": "#4a1414"}]}))
        st.plotly_chart(ui.style_fig(gauge, 280), key="intel_gauge")
    with m:
        trend = intel.risk_trend(evs)
        fig = go.Figure(go.Scatter(x=trend["hour"], y=trend["max_risk"], mode="lines+markers",
                                   line=dict(color="#f5b83d")))
        fig.update_layout(title="Highest risk per hour", yaxis_range=[0, 100])
        st.plotly_chart(ui.style_fig(fig, 280), key="intel_trend")

    left, right = st.columns([1, 1])
    with left:
        matrix = intel.severity_matrix(evs)
        heat = go.Figure(go.Heatmap(z=matrix.values, x=list(matrix.columns), y=list(matrix.index),
                                    colorscale="YlOrRd", text=matrix.values, texttemplate="%{text}",
                                    showscale=False))
        heat.update_layout(title="Unresolved events: domain x severity")
        st.plotly_chart(ui.style_fig(heat, 260), key="intel_matrix")
    with right:
        st.metric("Correlated incidents", len(incidents))
        st.metric("Still active", len(intel.active_incidents(incidents)))

    st.subheader("Correlated incidents")
    if not incidents:
        st.info("No events from two or more domains fall inside the window. Try a wider window.")
    for inc in sorted(incidents, key=lambda i: i["score"], reverse=True):
        with st.expander(f"{inc['id']}  |  {inc['level']}  |  score {inc['score']}  |  "
                         f"{' + '.join(inc['domains'])}  |  {inc['start'][:16].replace('T', ' ')} UTC"):
            st.dataframe(ui.events_dataframe(inc["events"]), hide_index=True)

    st.subheader("Report")
    if not auth.has_permission(user["role"], "download_reports"):
        st.info("Your role cannot generate reports.")
        return
    if st.button("Generate report", key="intel_report"):
        report = intel.build_report(evs, window, user["username"])
        st.session_state["intel_report"] = {"md": intel.render_markdown(report),
                                            "html": intel.render_html(report), "score": report["score"]}
        audit.log(user["id"], "REPORT_GENERATED", f"score={report['score']} window={window}")
    saved = st.session_state.get("intel_report")
    if saved:
        st.success(f"Report ready (risk score {saved['score']}). It uses the same numbers as this screen.")
        d1, d2 = st.columns(2)
        d1.download_button("Download Markdown", saved["md"], file_name="defendx_report.md",
                           mime="text/markdown", key="dl_md")
        d2.download_button("Download HTML", saved["html"], file_name="defendx_report.html",
                           mime="text/html", key="dl_html")
        with st.expander("Preview (Markdown)"):
            st.markdown(saved["md"])
