"""Radar Simulation page (FR-3)."""
import math

import plotly.graph_objects as go
import streamlit as st

from .. import auth, events, services
from .. import simulation as sim
from ..ui import components as ui

IFF_STYLE = {"FRIEND": ("#3ddc84", "circle"), "CIVIL": ("#4aa8ff", "diamond"),
             "UNKNOWN": ("#ff5d5d", "x")}


def _polar(x: float, y: float) -> tuple[float, float]:
    return math.hypot(x, y), sim.bearing_deg(x, y)


def ppi_figure(radar: sim.RadarSim):
    fig = go.Figure()
    zx, zy, zr = sim.RESTRICTED_ZONE
    pts = [_polar(zx + zr * math.cos(math.radians(a)), zy + zr * math.sin(math.radians(a)))
           for a in range(0, 361, 6)]
    fig.add_trace(go.Scatterpolar(r=[p[0] for p in pts], theta=[p[1] for p in pts], mode="lines",
                                  fill="toself", fillcolor="rgba(255,93,93,0.18)",
                                  line=dict(color="#ff5d5d", dash="dash"), name="Restricted zone"))
    ang = radar.sweep_angle
    fig.add_trace(go.Scatterpolar(r=[0, sim.RANGE_KM], theta=[ang, ang], mode="lines",
                                  line=dict(color="#19c3a6", width=3), name="Sweep"))
    for t in radar.tracks:
        color, _ = IFF_STYLE[t["iff"]]
        if len(t["trail"]) > 1:
            trail = [_polar(x, y) for x, y in t["trail"]]
            fig.add_trace(go.Scatterpolar(r=[p[0] for p in trail], theta=[p[1] for p in trail],
                                          mode="lines", line=dict(color=color, width=1),
                                          opacity=0.5, showlegend=False, hoverinfo="skip"))
    for iff, (color, symbol) in IFF_STYLE.items():
        group = [t for t in radar.tracks if t["iff"] == iff]
        if group:
            polar = [_polar(t["x"], t["y"]) for t in group]
            fig.add_trace(go.Scatterpolar(
                r=[p[0] for p in polar], theta=[p[1] for p in polar], mode="markers+text",
                text=[t["id"] for t in group], textposition="top center", name=iff,
                marker=dict(color=color, symbol=symbol, size=11)))
    fig.update_layout(
        polar=dict(bgcolor="#0a1a1a",
                   radialaxis=dict(range=[0, sim.RANGE_KM], tickvals=[20, 40, 60, 80, 100],
                                   ticksuffix=" km", gridcolor="#1e4d4d"),
                   angularaxis=dict(direction="clockwise", rotation=90, gridcolor="#1e4d4d",
                                    tickmode="array", tickvals=list(range(0, 360, 45)),
                                    ticktext=["N", "NE", "E", "SE", "S", "SW", "W", "NW"])),
        title="Plan position indicator (100 km)", legend=dict(orientation="h", y=-0.08))
    return ui.style_fig(fig, 640)


def render(user: dict) -> None:
    if not ui.require_permission(user, "view_sensors"):
        return
    st.title("Radar Simulation")
    ui.banner("Virtual radar picture with synthetic tracks. No real radar data is used.")
    can_run = auth.has_permission(user["role"], "run_simulations")

    if "radar_sim" not in st.session_state:
        st.session_state["radar_sim"] = sim.RadarSim(seed=42)
    radar: sim.RadarSim = st.session_state["radar_sim"]

    c1, c2, c3, c4 = st.columns(4)
    if c1.button("Inject unknown contact", disabled=not can_run, key="rd_inject"):
        tid = radar.inject_unknown()
        st.toast(f"Unidentified contact {tid} added")
    if c2.button("Step once", disabled=not can_run, key="rd_step"):
        services.log_radar_zone_entries(user, radar.step())
    if c3.button("Reset picture", disabled=not can_run, key="rd_reset"):
        st.session_state["radar_sim"] = radar = sim.RadarSim(seed=42)
    live = c4.toggle("Live sweep (every 2 s)", disabled=not can_run, key="radar_live")
    if not can_run:
        st.caption("Your role can view the picture but not control the simulation.")

    @st.fragment(run_every=2 if (live and can_run) else None)
    def picture():
        if live and can_run:
            entries = radar.step()
            if entries:
                services.log_radar_zone_entries(user, entries)
                st.error("ALERT: " + ", ".join(e["id"] for e in entries) +
                         " entered the restricted zone (HIGH event logged).")
        st.plotly_chart(ppi_figure(radar), key="rd_ppi")
        table = radar.snapshot().drop(columns=["x", "y"])
        st.dataframe(table, hide_index=True)
        st.caption(f"Step {radar.steps}  |  simulated time {radar.steps * sim.STEP_SECONDS // 60} min")

    picture()

    st.subheader("Radar event log")
    ui.event_table(events.list_events(domain="RADAR", limit=200), user, key="rd_events")
