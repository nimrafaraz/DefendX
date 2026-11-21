"""Administration page (FR-11)."""
import pandas as pd
import streamlit as st

from .. import audit, auth, config, events, services
from ..ui import components as ui


def _users_tab(user: dict) -> None:
    users = auth.list_users()
    st.dataframe(pd.DataFrame(users)[["id", "username", "display_name", "role", "active",
                                      "last_login", "created_at"]], hide_index=True)

    st.subheader("Create user")
    with st.form("create_user", clear_on_submit=True):
        a, b = st.columns(2)
        username = a.text_input("Username")
        display = b.text_input("Display name")
        c, d = st.columns(2)
        password = c.text_input("Password", type="password",
                                help="8+ characters with letters and digits")
        role = d.selectbox("Role", config.ROLES, index=config.ROLES.index("VIEWER"))
        if st.form_submit_button("Create user"):
            try:
                auth.create_user(username, password, role, display or None, actor_id=user["id"])
                st.success(f"User '{username}' created.")
            except ValueError as exc:
                st.error(str(exc))

    st.subheader("Manage existing user")
    by_id = {u["id"]: u for u in users}
    uid = st.selectbox("User", list(by_id), key="adm_user",
                       format_func=lambda i: f"{by_id[i]['username']} ({by_id[i]['role']}, "
                                             f"{'active' if by_id[i]['active'] else 'disabled'})")
    target = by_id[uid]
    c1, c2, c3 = st.columns(3)
    with c1:
        new_role = st.selectbox("New role", config.ROLES, index=config.ROLES.index(target["role"]),
                                key=f"adm_role_{uid}")
        if st.button("Change role", key=f"adm_role_btn_{uid}"):
            try:
                auth.set_role(uid, new_role, actor_id=user["id"])
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    with c2:
        st.write("Account status")
        label = "Disable account" if target["active"] else "Enable account"
        if st.button(label, key=f"adm_active_btn_{uid}"):
            try:
                auth.set_active(uid, not target["active"], actor_id=user["id"])
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    with c3:
        new_pw = st.text_input("New password", type="password", key=f"adm_pw_{uid}")
        if st.button("Reset password", key=f"adm_pw_btn_{uid}"):
            try:
                auth.reset_password(uid, new_pw, actor_id=user["id"])
                st.success("Password reset.")
            except ValueError as exc:
                st.error(str(exc))


def _audit_tab() -> None:
    actions = ["(all)"] + sorted({a["action"] for a in audit.recent(limit=1000)})
    choice = st.selectbox("Filter by action", actions, key="adm_audit_filter")
    rows = audit.recent(limit=300, action=None if choice == "(all)" else choice)
    st.dataframe(pd.DataFrame(rows, columns=["id", "ts", "username", "action", "detail"]),
                 hide_index=True)


def _demo_tab(user: dict) -> None:
    st.write(f"Events in store: **{events.count_events()}**")
    st.subheader("Regenerate demo history")
    st.caption(f"Deletes ALL current events and creates {config.DEMO_HISTORY_HOURS} hours of synthetic history.")
    confirm = st.checkbox("I understand this replaces all events", key="adm_confirm")
    if st.button("Regenerate 48 hours of history", disabled=not confirm, key="adm_regen"):
        n = services.seed_demo_history()
        audit.log(user["id"], "DEMO_DATA_REGENERATED", f"{n} events")
        st.success(f"Created {n} synthetic events.")
    st.subheader("Inject live scenario")
    if st.button("Inject multi-domain scenario now", key="adm_inject"):
        res = services.inject_scenario(user)
        st.success(f"Injected {len(res['event_ids'])} related events across RF, CYBER and RADAR.")


def render(user: dict) -> None:
    if not ui.require_permission(user, "admin"):
        return
    st.title("Administration")
    ui.banner()
    users_tab, audit_tab, demo_tab = st.tabs(["Users", "Audit log", "Demo data"])
    with users_tab:
        _users_tab(user)
    with audit_tab:
        _audit_tab()
    with demo_tab:
        _demo_tab(user)
