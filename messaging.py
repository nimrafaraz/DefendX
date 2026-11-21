"""Encrypted user-to-user messaging.

Each pair of users gets its own key: HKDF-SHA256(master key, info = both user ids).
Messages are encrypted with Fernet (AES-128-CBC + HMAC-SHA256), so any change to
the stored ciphertext is detected and rejected when the message is read.

LIMIT (also shown in the docs): this is server-side encryption at rest, NOT
end-to-end. Anyone who can read data/master.key can read every conversation.
"""
from __future__ import annotations

import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import config, db
from .timeutil import now_iso

TAMPERED_TEXT = "[message could not be decrypted - integrity check failed]"


# -------------------------------------------------------------- key handling
def load_master_key() -> bytes:
    """Load data/master.key, creating a new random 32-byte key if it is missing."""
    path = config.key_path()
    if not path.exists():
        path.write_text(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # not all file systems support this (e.g. some Windows setups)
    try:
        key = base64.urlsafe_b64decode(path.read_text().strip().encode("ascii"))
    except Exception as exc:
        raise ValueError("master.key is corrupt (not valid base64).") from exc
    if len(key) != 32:
        raise ValueError("master.key is corrupt (wrong length).")
    return key


def conversation_key(user_a: int, user_b: int) -> bytes:
    """Derive the Fernet key for a pair. Same key for (a, b) and (b, a)."""
    low, high = sorted((int(user_a), int(user_b)))
    raw = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=f"defendx-conversation:{low}:{high}".encode("ascii"),
    ).derive(load_master_key())
    return base64.urlsafe_b64encode(raw)


def _fernet(user_a: int, user_b: int) -> Fernet:
    return Fernet(conversation_key(user_a, user_b))


# ---------------------------------------------------------------- operations
def send_message(sender_id: int, recipient_id: int, text: str) -> int:
    text = (text or "").strip()
    if not text:
        raise ValueError("Message is empty.")
    if len(text) > config.MAX_MESSAGE_LENGTH:
        raise ValueError(f"Message is longer than {config.MAX_MESSAGE_LENGTH} characters.")
    if sender_id == recipient_id:
        raise ValueError("You cannot message yourself.")
    recipient = db.query_one("SELECT id, active FROM users WHERE id = ?", (recipient_id,))
    if not recipient or not recipient["active"]:
        raise ValueError("Recipient does not exist or is disabled.")
    token = _fernet(sender_id, recipient_id).encrypt(text.encode("utf-8")).decode("ascii")
    return db.execute(
        "INSERT INTO messages (ts, sender_id, recipient_id, ciphertext, is_read) "
        "VALUES (?,?,?,?,0)", (now_iso(), sender_id, recipient_id, token),
    )


def _rows_between(user_id: int, other_id: int) -> list[dict]:
    return db.query(
        "SELECT * FROM messages WHERE (sender_id = ? AND recipient_id = ?) "
        "OR (sender_id = ? AND recipient_id = ?) ORDER BY id",
        (user_id, other_id, other_id, user_id),
    )


def get_conversation(user_id: int, other_id: int, mark_read: bool = True,
                     limit: int = 200) -> list[dict]:
    """Decrypt and return the conversation (oldest first); marks incoming as read."""
    fernet = _fernet(user_id, other_id)
    out = []
    for row in _rows_between(user_id, other_id)[-limit:]:
        try:
            text, ok = fernet.decrypt(row["ciphertext"].encode("ascii")).decode("utf-8"), True
        except (InvalidToken, ValueError):
            text, ok = TAMPERED_TEXT, False
        out.append({"id": row["id"], "ts": row["ts"], "sender_id": row["sender_id"],
                    "recipient_id": row["recipient_id"], "text": text, "ok": ok,
                    "was_unread": bool(row["recipient_id"] == user_id and not row["is_read"])})
    if mark_read:
        db.execute("UPDATE messages SET is_read = 1 WHERE recipient_id = ? AND sender_id = ? "
                   "AND is_read = 0", (user_id, other_id))
    return out


def unread_counts(user_id: int) -> dict[int, int]:
    rows = db.query(
        "SELECT sender_id, COUNT(*) AS n FROM messages WHERE recipient_id = ? AND is_read = 0 "
        "GROUP BY sender_id", (user_id,))
    return {r["sender_id"]: r["n"] for r in rows}


def total_unread(user_id: int) -> int:
    return sum(unread_counts(user_id).values())


def stored_ciphertexts(user_id: int, other_id: int, limit: int = 3) -> list[dict]:
    """What the database really holds (for the 'show me the ciphertext' expander)."""
    rows = _rows_between(user_id, other_id)[-limit:]
    return [{"id": r["id"], "ts": r["ts"], "ciphertext": r["ciphertext"]} for r in rows]
