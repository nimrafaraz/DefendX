"""Electronic Activity page (FR-1)."""
import numpy as np
import plotly.graph_objects as go
import streamlit as st

from .. import auth, events, services
from .. import simulation as sim
from ..ui import components as ui


def _spectrum_figure(sweep: dict, detections: list[dict]):
    fig = go.Figure()
    fig.add_scatter(x=sweep["freqs"], y=sweep["power_dbm"], mode="lines", name="Spectrum",
                    line=dict(color="#4aa8ff", width=1.5))
    fig.add_scatter(x=[e["freq_mhz"] for e in sim.AUTHORISED_EMITTERS],
                    y=[e["power_dbm"] + 6 for e in sim.AUTHORISED_EMITTERS], mode="markers+text",
                    text=[e["name"] for e in sim.AUTHORISED_EMITTERS], textposition="top center",
                    marker=dict(symbol="triangle-down", color="#19c3a6", size=9), name="Authorised plan")
    marked = [d for d in detections if d["freq_mhz"] is not None]
    if marked:
        fig.add_scatter(x=[d["freq_mhz"] for d in marked],
                        y=[d["power_dbm"] if d["power_dbm"] is not None else sim.NOISE_FLOOR_DBM + 10
                           for d in marked],
                        mode="markers", name="Detection",
                        marker=dict(symbol="x", color="#ff5d5d", size=14, line=dict(width=2)))
    fig.update_layout(title="Spectrum 400-470 MHz", xaxis_title="Frequency (MHz)",
                      yaxis_title="Power (dBm)", yaxis_range=[-115, -40])
    return ui.style_fig(fig, 380)


def render(user: dict) -> None:
    if not ui.require_permission(user, "view_sensors"):
        return
    st.title("Electronic Activity Monitoring")
    ui.banner()
    can_run = auth.has_permission(user["role"], "run_simulations")

    if "rf_result" not in st.session_state:       # baseline view: shown, but nothing is logged
        sweep = sim.simulate_sweep(7, "Normal")
        st.session_state["rf_result"] = {
            "sweep": sweep, "seed": 7, "scenario": "Normal (baseline view, not logged)",
            "detections": sim.detect_rf(sweep["freqs"], sweep["power_dbm"]),
            "waterfall": sim.simulate_waterfall(7, "Normal")}

    c1, c2, c3 = st.columns([2, 1, 1])
    scenario = c1.selectbox("Scenario", sim.RF_SCENARIOS, disabled=not can_run, key="rf_scenario")
    seed_in = c2.number_input("Seed (0 = random)", min_value=0, max_value=999_999, value=0,
                              disabled=not can_run, key="rf_seed")
    c3.write("")
    if c3.button("Run scan", disabled=not can_run, key="rf_run"):
        result = services.run_rf_scan(user, scenario, int(seed_in) or None)
        result["scenario"] = scenario
        result["waterfall"] = sim.simulate_waterfall(result["seed"], scenario)
        st.session_state["rf_result"] = result
        st.rerun()
    if not can_run:
        st.caption("Your role can view this page but not run scans.")

    res = st.session_state["rf_result"]
    st.caption(f"Showing: {res['scenario']}  |  seed {res['seed']}  |  "
               f"{len(res['detections'])} detection(s)")
    st.plotly_chart(_spectrum_figure(res["sweep"], res["detections"]), key="rf_spectrum")

    n = res["waterfall"].shape[0]
    wf = go.Figure(go.Heatmap(z=res["waterfall"], x=sim.FREQS, y=[f"-{n - 1 - i}" for i in range(n)],
                              colorscale="Viridis", zmin=-110, zmax=-50,
                              colorbar=dict(title=dict(text="dBm"))))
    wf.update_layout(title="Waterfall (30 sweeps, newest at the bottom)", xaxis_title="Frequency (MHz)",
                     yaxis_title="Sweeps ago")
    st.plotly_chart(ui.style_fig(wf, 340), key="rf_waterfall")

    st.subheader("Detections in this scan")
    if res["detections"]:
        st.dataframe([{"Type": d["kind"], "Severity": d["severity"], "Title": d["title"],
                       "Details": d["details"]} for d in res["detections"]], hide_index=True)
    else:
        st.success("No anomalies: the sweep matches the authorised plan.")

    st.subheader("RF event log")
    ui.event_table(events.list_events(domain="RF", limit=200), user, key="rf_events")
