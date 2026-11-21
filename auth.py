"""Accounts, password hashing (scrypt), lockout, roles and user management."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from datetime import timedelta

from . import audit, config, db
from .timeutil import from_iso, now_iso, to_iso, utcnow

GENERIC_LOGIN_ERROR = "Invalid username or password."
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_PUBLIC_COLUMNS = (
    "id, username, display_name, role, active, failed_attempts, "
    "locked_until, created_at, last_login"
)


# ---------------------------------------------------------------- hashing
def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Return (hash_hex, salt_hex) using scrypt and a 16-byte random salt."""
    salt = salt if salt is not None else os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=config.SCRYPT_N, r=config.SCRYPT_R, p=config.SCRYPT_P, dklen=32,
    )
    return digest.hex(), salt.hex()


def verify_password(password: str, hash_hex: str, salt_hex: str) -> bool:
    candidate, _ = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(candidate, hash_hex)  # constant-time comparison


# --------------------------------------------------------------- policies
def validate_password(password: str) -> str | None:
    """Return an error message, or None if the password meets the policy."""
    if len(password) < config.PASSWORD_MIN_LENGTH:
        return f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must contain both letters and digits."
    return None


def validate_username(username: str) -> str | None:
    if not (config.USERNAME_MIN_LENGTH <= len(username) <= config.USERNAME_MAX_LENGTH):
        return (f"Username must be {config.USERNAME_MIN_LENGTH}-"
                f"{config.USERNAME_MAX_LENGTH} characters.")
    if not _USERNAME_RE.match(username):
        return "Username may only contain letters, digits, '_', '.' and '-'."
    return None


def has_permission(role: str | None, permission: str) -> bool:
    return permission in config.PERMISSIONS.get(role or "", set())


# ------------------------------------------------------------------ users
def _public(row: dict | None) -> dict | None:
    if row is None:
        return None
    return {k: row[k] for k in row if k not in ("password_hash", "salt")}


def get_user(user_id: int) -> dict | None:
    return db.query_one(f"SELECT {_PUBLIC_COLUMNS} FROM users WHERE id = ?", (user_id,))


def get_user_by_username(username: str) -> dict | None:
    return db.query_one(
        f"SELECT {_PUBLIC_COLUMNS} FROM users WHERE username = ? COLLATE NOCASE", (username,)
    )


def get_active_user(user_id: int | None) -> dict | None:
    """Re-check the account. Used on every page run so changes take effect at once."""
    if user_id is None:
        return None
    user = get_user(user_id)
    return user if user and user["active"] else None


def list_users() -> list[dict]:
    return db.query(f"SELECT {_PUBLIC_COLUMNS} FROM users ORDER BY username COLLATE NOCASE")


def count_active_admins() -> int:
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM users WHERE role = 'ADMIN' AND active = 1"
    )
    return row["n"] if row else 0


def create_user(username: str, password: str, role: str,
                display_name: str | None = None, actor_id: int | None = None) -> dict:
    username = username.strip()
    err = validate_username(username) or validate_password(password)
    if err:
        raise ValueError(err)
    if role not in config.ROLES:
        raise ValueError("Unknown role.")
    if get_user_by_username(username):
        raise ValueError("That username already exists.")
    pw_hash, salt = hash_password(password)
    user_id = db.execute(
        "INSERT INTO users (username, display_name, role, password_hash, salt, active, "
        "created_at) VALUES (?,?,?,?,?,1,?)",
        (username, (display_name or username).strip(), role, pw_hash, salt, now_iso()),
    )
    audit.log(actor_id, "USER_CREATED", f"{username} role={role}")
    return get_user(user_id)


def _guard_last_admin(user_id: int, new_role: str | None = None,
                      new_active: bool | None = None) -> None:
    target = get_user(user_id)
    if not target:
        raise ValueError("User not found.")
    is_active_admin = target["role"] == config.ROLE_ADMIN and target["active"]
    loses_admin = (new_role is not None and new_role != config.ROLE_ADMIN) or new_active is False
    if is_active_admin and loses_admin and count_active_admins() <= 1:
        raise ValueError("Cannot remove or demote the last active administrator.")


def set_role(user_id: int, role: str, actor_id: int | None = None) -> None:
    if role not in config.ROLES:
        raise ValueError("Unknown role.")
    _guard_last_admin(user_id, new_role=role)
    db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    audit.log(actor_id, "ROLE_CHANGED", f"user_id={user_id} new_role={role}")


def set_active(user_id: int, active: bool, actor_id: int | None = None) -> None:
    _guard_last_admin(user_id, new_active=active)
    db.execute("UPDATE users SET active = ? WHERE id = ?", (1 if active else 0, user_id))
    audit.log(actor_id, "USER_ENABLED" if active else "USER_DISABLED", f"user_id={user_id}")


def reset_password(user_id: int, new_password: str, actor_id: int | None = None) -> None:
    err = validate_password(new_password)
    if err:
        raise ValueError(err)
    if not get_user(user_id):
        raise ValueError("User not found.")
    pw_hash, salt = hash_password(new_password)
    db.execute(
        "UPDATE users SET password_hash = ?, salt = ?, failed_attempts = 0, "
        "locked_until = NULL WHERE id = ?", (pw_hash, salt, user_id),
    )
    audit.log(actor_id, "PASSWORD_RESET", f"user_id={user_id}")


def seed_demo_users() -> None:
    """Create the four demo accounts if the users table is empty."""
    if db.query_one("SELECT COUNT(*) AS n FROM users")["n"] == 0:
        for username, password, role, display in config.DEMO_ACCOUNTS:
            create_user(username, password, role, display)


# ------------------------------------------------------------------ login
def authenticate(username: str, password: str, now=None) -> tuple[dict | None, str]:
    """Check a login. Returns (user, "") on success or (None, error message).

    Unknown user and wrong password give the same error, and a dummy hash is
    computed for unknown users so response time does not reveal which it was.
    """
    now = now or utcnow()
    username = (username or "").strip()
    row = db.query_one("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,))

    if row is None:
        hash_password(password or "")  # equalise timing
        audit.log(None, "LOGIN_FAILED", f"unknown user '{username[:40]}'")
        return None, GENERIC_LOGIN_ERROR

    if row["locked_until"] and from_iso(row["locked_until"]) > now:
        audit.log(row["id"], "LOGIN_BLOCKED", "account locked")
        return None, f"Account temporarily locked. Try again in {config.LOCKOUT_MINUTES} minutes."

    ok = verify_password(password or "", row["password_hash"], row["salt"])
    if not ok or not row["active"]:
        attempts = row["failed_attempts"] + 1
        if attempts >= config.MAX_FAILED_ATTEMPTS:
            locked_until = to_iso(now + timedelta(minutes=config.LOCKOUT_MINUTES))
            db.execute("UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                       (locked_until, row["id"]))
            audit.log(row["id"], "LOCKOUT", f"locked after {config.MAX_FAILED_ATTEMPTS} failures")
        else:
            db.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, row["id"]))
            audit.log(row["id"], "LOGIN_FAILED", "bad password or disabled account")
        return None, GENERIC_LOGIN_ERROR

    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? "
               "WHERE id = ?", (to_iso(now), row["id"]))
    audit.log(row["id"], "LOGIN", "success")
    return get_user(row["id"]), ""
