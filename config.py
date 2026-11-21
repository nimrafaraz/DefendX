"""Central configuration: paths, roles, permissions, thresholds, demo accounts.

Everything you might want to tune lives here (or in the constants at the top of
simulation.py), so you never have to hunt through the pages.
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def data_dir() -> Path:
    """Folder holding the database and master key.

    Read from the DEFENDX_DATA_DIR environment variable at call time, which is how
    the tests give themselves a private temporary folder.
    """
    path = Path(os.environ.get("DEFENDX_DATA_DIR") or (BASE_DIR / "data"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "defendx.db"


def key_path() -> Path:
    return data_dir() / "master.key"


# ----------------------------------------------------------------- roles
ROLE_ADMIN = "ADMIN"
ROLE_ANALYST = "ANALYST"
ROLE_OPERATOR = "OPERATOR"
ROLE_VIEWER = "VIEWER"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_OPERATOR, ROLE_VIEWER)

# Permission names used throughout the app.
PERMISSIONS = {
    ROLE_ADMIN: {
        "view_dashboard", "view_sensors", "run_simulations", "manage_events",
        "view_intel", "download_reports", "messaging", "admin",
    },
    ROLE_ANALYST: {
        "view_dashboard", "view_sensors", "manage_events",
        "view_intel", "download_reports", "messaging",
    },
    ROLE_OPERATOR: {
        "view_dashboard", "view_sensors", "run_simulations", "manage_events",
        "messaging",
    },
    ROLE_VIEWER: {"view_dashboard", "view_sensors"},
}

# ------------------------------------------------------------- security
PASSWORD_MIN_LENGTH = 8
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
SCRYPT_N, SCRYPT_R, SCRYPT_P = 16384, 8, 1
MAX_MESSAGE_LENGTH = 2000

# --------------------------------------------------------------- events
DOMAINS = ("RF", "CYBER", "RADAR")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
STATUSES = ("OPEN", "ACKNOWLEDGED", "RESOLVED")
SEVERITY_RISK = {"LOW": 15, "MEDIUM": 40, "HIGH": 70, "CRITICAL": 90}

# ---------------------------------------------------------- intelligence
SERIOUS_RISK = 50            # an event at/above this counts as "serious activity"
EXTRA_DOMAIN_POINTS = 6      # per additional domain with serious activity
VOLUME_MAX_POINTS = 5        # cap on the volume bonus
VOLUME_FULL_AT = 20          # unresolved events needed for the full volume bonus
CROSS_DOMAIN_BONUS = 5       # per extra domain inside one incident
DEFAULT_CORRELATION_MINUTES = 10
LEVEL_BOUNDS = ((25, "LOW"), (50, "MEDIUM"), (75, "HIGH"))  # otherwise CRITICAL

# ------------------------------------------------------------- demo data
DEMO_ACCOUNTS = (
    ("admin", "Admin@2026", ROLE_ADMIN, "Alex Admin"),
    ("analyst", "Analyst@2026", ROLE_ANALYST, "Anna Analyst"),
    ("operator", "Operator@2026", ROLE_OPERATOR, "Omar Operator"),
    ("viewer", "Viewer@2026", ROLE_VIEWER, "Vera Viewer"),
)
DEMO_HISTORY_HOURS = 48
