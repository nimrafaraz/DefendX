"""Smoke test: render every page for every role with Streamlit's AppTest runner.

Skipped automatically if Streamlit is not installed. This checks that pages run
without raising an exception; it does NOT check how charts look.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

try:
    from streamlit.testing.v1 import AppTest
except Exception:                                   # Streamlit missing or too old
    AppTest = None

ROOT = Path(__file__).resolve().parent.parent
PAGE_KEYS = {"dashboard": "view_dashboard", "rf": "view_sensors", "cyber": "view_sensors",
             "radar": "view_sensors", "intel": "view_intel", "comms": "messaging",
             "admin": "admin"}
_tmp = None


def setUpModule():
    # One shared data folder for the whole module (the app caches its start-up step).
    global _tmp
    _tmp = tempfile.mkdtemp(prefix="defendx_smoke_")
    os.environ["DEFENDX_DATA_DIR"] = _tmp
    from defendx import db, services
    db.init_db()
    services.ensure_demo_data()


def tearDownModule():
    os.environ.pop("DEFENDX_DATA_DIR", None)
    shutil.rmtree(_tmp, ignore_errors=True)


@unittest.skipIf(AppTest is None, "streamlit not installed")
class SmokeTests(unittest.TestCase):
    def new_app(self):
        return AppTest.from_file(str(ROOT / "app.py"), default_timeout=90)

    def test_login_screen_renders(self):
        at = self.new_app().run()
        self.assertFalse(at.exception)
        self.assertGreaterEqual(len(at.text_input), 2)

    def test_every_allowed_page_renders_for_every_role(self):
        from defendx import auth, config
        for username, _, role, _ in config.DEMO_ACCOUNTS:
            uid = auth.get_user_by_username(username)["id"]
            for key, permission in PAGE_KEYS.items():
                if not auth.has_permission(role, permission):
                    continue
                with self.subTest(role=role, page=key):
                    at = self.new_app()
                    at.session_state["user_id"] = uid
                    at.session_state["nav"] = key
                    at.run()
                    self.assertFalse(at.exception, f"{role}/{key}: {at.exception}")


if __name__ == "__main__":
    unittest.main()
