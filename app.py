"""DEFEND-X entry point: login, sidebar navigation and role checks.

Run with:  streamlit run app.py
"""
import streamlit as st

from defendx import audit, auth, config, db, messaging, services
from defendx.pages import (admin, cyber_defence, dashboard, intel_analysis, radar_view,
                           rf_monitor, secure_comms)
from defendx.ui import theme

st.set_page_config(page_title="DEFEND-X", page_icon="🛡️", layout="wide")
theme.apply_theme()

# key -> (menu label, page module, permission needed)
PAGES = {
    "dashboard": ("Dashboard", dashboard, "view_dashboard"),
    "rf": ("Electronic Activity", rf_monitor, "view_sensors"),
    "cyber": ("Cyber Defence", cyber_defence, "view_sensors"),
    "radar": ("Radar Simulation", radar_view, "view_sensors"),
    "intel": ("Intelligence", intel_analysis, "view_intel"),
    "comms": ("Secure Comms", secure_comms, "messaging"),
    "admin": ("Administration", admin, "admin"),
}


@st.cache_resource
def bootstrap() -> bool:
    """First-run set-up: tables, demo accounts and 48 h of synthetic history."""
    db.init_db()
    services.ensure_demo_data()
    return True


def show_login(message: str = "") -> None:
    st.title("🛡️ DEFEND-X")
    st.caption("Integrated Multi-Domain Defence Awareness System - educational simulation")
    if message:
        st.warning(message)
    left, right = st.columns([1, 1])
    with left:
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            if st.form_submit_button("Sign in"):
                user, error = auth.authenticate(username, password)
                if user:
                    st.session_state["user_id"] = user["id"]
                    st.rerun()
                else:
                    st.error(error)
    with right:
        st.markdown("**Demo accounts** (synthetic training environment)")
        st.table({"Username": [a[0] for a in config.DEMO_ACCOUNTS],
                  "Password": [a[1] for a in config.DEMO_ACCOUNTS],
                  "Role": [a[2] for a in config.DEMO_ACCOUNTS]})


def main() -> None:
    bootstrap()
    user_id = st.session_state.get("user_id")
    if user_id is None:
        show_login()
        return

    user = auth.get_active_user(user_id)          # re-checked on every page run
    if user is None:
        st.session_state.clear()
        show_login("Your session ended because the account was disabled or removed.")
        return

    allowed = {k: v for k, v in PAGES.items() if auth.has_permission(user["role"], v[2])}
    unread = messaging.total_unread(user["id"]) if "comms" in allowed else 0

    st.sidebar.title("🛡️ DEFEND-X")
    st.sidebar.write(f"**{user['display_name']}**  \nRole: `{user['role']}`")

    def label(key: str) -> str:
        text = allowed[key][0]
        return f"{text} ({unread})" if key == "comms" and unread else text

    keys = list(allowed)
    if st.session_state.get("nav") not in keys:
        st.session_state["nav"] = keys[0]
    page_key = st.sidebar.radio("Navigate", keys, format_func=label, key="nav")
    if st.sidebar.button("Sign out"):
        audit.log(user["id"], "LOGOUT", "")
        st.session_state.clear()
        st.rerun()
    st.sidebar.caption("Synthetic data only. Educational use.")

    try:
        allowed[page_key][1].render(user)
    except PermissionError as exc:
        st.error(str(exc))


main()
