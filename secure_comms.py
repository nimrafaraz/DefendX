"""Secure Communication page (FR-10)."""
import streamlit as st

from .. import auth, messaging
from ..ui import components as ui


def render(user: dict) -> None:
    if not ui.require_permission(user, "messaging"):
        return
    st.title("Secure Communication")
    ui.banner("Messages are encrypted per conversation and stored as ciphertext. This is server-side "
              "encryption at rest, not end-to-end: whoever can read data/master.key can read everything.")

    others = [u for u in auth.list_users() if u["active"] and u["id"] != user["id"]]
    if not others:
        st.info("There are no other active users to message.")
        return
    counts = messaging.unread_counts(user["id"])
    labels = {u["id"]: f"{u['display_name']} ({u['username']})"
                       + (f"  -  {counts[u['id']]} unread" if counts.get(u["id"]) else "")
              for u in others}
    other_id = st.selectbox("Conversation with", list(labels), format_func=lambda i: labels[i],
                            key="comms_other")
    other = next(u for u in others if u["id"] == other_id)

    with st.form("send_form", clear_on_submit=True):
        text = st.text_area("New message", max_chars=2000, height=90)
        sent = st.form_submit_button("Send encrypted message")
    if sent:
        try:
            messaging.send_message(user["id"], other_id, text)
        except ValueError as exc:
            st.error(str(exc))

    conversation = messaging.get_conversation(user["id"], other_id)   # also marks incoming as read
    st.subheader(f"Conversation with {other['display_name']}")
    if not conversation:
        st.caption("No messages yet.")
    for m in conversation:
        mine = m["sender_id"] == user["id"]
        with st.chat_message("user" if mine else "assistant"):
            who = "You" if mine else other["display_name"]
            tag = " (new)" if m["was_unread"] else ""
            st.markdown(f"**{who}**{tag} &nbsp; `{m['ts'][:19].replace('T', ' ')} UTC`")
            (st.write if m["ok"] else st.error)(m["text"])
    st.button("Refresh", key="comms_refresh")

    with st.expander("What the database actually stores"):
        stored = messaging.stored_ciphertexts(user["id"], other_id)
        if not stored:
            st.caption("Nothing stored yet.")
        for row in stored:
            st.code(f"message #{row['id']}  {row['ts'][:19]}\n{row['ciphertext']}", language="text")
