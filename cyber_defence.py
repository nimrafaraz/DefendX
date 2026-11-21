"""Cyber Defence page (FR-2)."""
import plotly.graph_objects as go
import streamlit as st

from .. import auth, events, services
from .. import simulation as sim
from ..ui import components as ui

LABEL_COLOR = {"benign": "#3b5b8c", "Port scan": "#f5d24a", "Brute force": "#ff9b4a",
               "Data exfiltration": "#ff5d5d", "Traffic flood": "#b07cff"}


def render(user: dict) -> None:
    if not ui.require_permission(user, "view_sensors"):
        return
    st.title("Cyber Defence")
    ui.banner("Synthetic flow records only. Attack patterns are rows in a table; nothing is sent "
              "over a network. Outside addresses use reserved documentation ranges.")
    can_run = auth.has_permission(user["role"], "run_simulations")

    if "cyber_result" not in st.session_state:    # baseline view, nothing logged
        flows = sim.build_cyber_scenario(7, "Normal traffic")
        dets, labelled = sim.detect_cyber(flows)
        st.session_state["cyber_result"] = {"flows": labelled, "detections": dets, "seed": 7,
                                            "scenario": "Normal traffic (baseline view, not logged)"}

    c1, c2, c3 = st.columns([2, 1, 1])
    scenario = c1.selectbox("Traffic pattern", sim.CYBER_SCENARIOS, disabled=not can_run, key="cy_scenario")
    seed_in = c2.number_input("Seed (0 = random)", min_value=0, max_value=999_999, value=0,
                              disabled=not can_run, key="cy_seed")
    c3.write("")
    if c3.button("Run analysis", disabled=not can_run, key="cy_run"):
        result = services.run_cyber_scan(user, scenario, int(seed_in) or None)
        result["scenario"] = scenario
        st.session_state["cyber_result"] = result
        st.rerun()
    if not can_run:
        st.caption("Your role can view this page but not run analyses.")

    res = st.session_state["cyber_result"]
    flows = res["flows"]
    st.caption(f"Showing: {res['scenario']}  |  seed {res['seed']}  |  {len(flows)} flows  |  "
               f"{len(res['detections'])} detection(s)")

    if res["detections"]:
        for d in res["detections"]:
            st.warning(f"**{d['severity']}** - {d['title']}: {d['details']}")
    else:
        st.success("No threats detected in this traffic window.")

    per_min = flows.assign(minute=flows["ts"].dt.floor("min")).groupby(["minute", "detected"]).size() \
        .reset_index(name="flows")
    fig = go.Figure()
    for label in ["benign"] + [x for x in sim.CYBER_SCENARIOS[1:]]:
        d = per_min[per_min["detected"] == label]
        if not d.empty:
            fig.add_bar(x=d["minute"], y=d["flows"], name=label, marker_color=LABEL_COLOR[label])
    fig.update_layout(barmode="stack", title="Flows per minute", xaxis_title="Time (UTC)",
                      yaxis_title="Flows")
    st.plotly_chart(ui.style_fig(fig, 320), key="cy_chart")

    st.subheader("Flow records (flagged first)")
    shown = flows.assign(flagged=flows["detected"] != "benign") \
        .sort_values(["flagged", "ts"], ascending=[False, True]).head(300)
    table = shown[["ts", "src", "dst", "dst_port", "proto", "bytes", "packets", "failed_logins",
                   "detected"]].copy()
    table["ts"] = table["ts"].dt.strftime("%H:%M:%S")
    st.dataframe(table, hide_index=True)

    st.subheader("Cyber event log")
    ui.event_table(events.list_events(domain="CYBER", limit=200), user, key="cy_events")
