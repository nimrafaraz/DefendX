"""Shared test helper: every test gets its own temporary data folder."""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TempDataCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="defendx_test_")
        self._old = os.environ.get("DEFENDX_DATA_DIR")
        os.environ["DEFENDX_DATA_DIR"] = self._tmp
        from defendx import db
        db.init_db()

    def tearDown(self):
        if self._old is None:
            os.environ.pop("DEFENDX_DATA_DIR", None)
        else:
            os.environ["DEFENDX_DATA_DIR"] = self._old
        shutil.rmtree(self._tmp, ignore_errors=True)
