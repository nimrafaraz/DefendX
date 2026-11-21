import unittest
from datetime import timedelta

from defendx import audit, auth, config
from defendx.timeutil import utcnow
from tests.helpers import TempDataCase


class AuthTests(TempDataCase):
    def make(self, name="bob", pw="Passw0rdX", role="VIEWER"):
        return auth.create_user(name, pw, role)

    def test_hash_is_salted_and_verifies(self):
        h1, s1 = auth.hash_password("Secret123")
        h2, s2 = auth.hash_password("Secret123")
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(h1, h2)
        self.assertEqual(len(bytes.fromhex(s1)), 16)
        self.assertTrue(auth.verify_password("Secret123", h1, s1))
        self.assertFalse(auth.verify_password("secret123", h1, s1))

    def test_login_success(self):
        self.make()
        user, err = auth.authenticate("bob", "Passw0rdX")
        self.assertEqual(err, "")
        self.assertEqual(user["username"], "bob")
        self.assertNotIn("password_hash", user)

    def test_username_is_case_insensitive(self):
        self.make("Carol")
        self.assertIsNotNone(auth.authenticate("cAROL", "Passw0rdX")[0])
        with self.assertRaises(ValueError):
            auth.create_user("CAROL", "Passw0rdX", "VIEWER")

    def test_unknown_user_and_wrong_password_give_identical_error(self):
        self.make()
        _, e1 = auth.authenticate("nobody", "Passw0rdX")
        _, e2 = auth.authenticate("bob", "wrongpass1")
        self.assertEqual(e1, e2)
        self.assertEqual(e1, auth.GENERIC_LOGIN_ERROR)

    def test_lockout_after_five_failures_then_expires(self):
        self.make()
        for _ in range(config.MAX_FAILED_ATTEMPTS):
            auth.authenticate("bob", "badpass123")
        user, err = auth.authenticate("bob", "Passw0rdX")        # correct, but locked
        self.assertIsNone(user)
        self.assertIn("locked", err.lower())
        later = utcnow() + timedelta(minutes=config.LOCKOUT_MINUTES + 1)
        user, err = auth.authenticate("bob", "Passw0rdX", now=later)
        self.assertIsNotNone(user)

    def test_success_resets_failure_counter(self):
        self.make()
        for _ in range(3):
            auth.authenticate("bob", "badpass123")
        auth.authenticate("bob", "Passw0rdX")
        self.assertEqual(auth.get_user_by_username("bob")["failed_attempts"], 0)

    def test_disabled_user_cannot_log_in(self):
        u = self.make()
        self.make("admin2", role="ADMIN")
        auth.set_active(u["id"], False)
        self.assertIsNone(auth.authenticate("bob", "Passw0rdX")[0])
        self.assertIsNone(auth.get_active_user(u["id"]))

    def test_password_policy(self):
        self.assertIsNotNone(auth.validate_password("short1"))
        self.assertIsNotNone(auth.validate_password("onlyletters"))
        self.assertIsNotNone(auth.validate_password("12345678"))
        self.assertIsNone(auth.validate_password("Good1234"))
        with self.assertRaises(ValueError):
            auth.create_user("weak", "abc", "VIEWER")

    def test_username_policy(self):
        self.assertIsNotNone(auth.validate_username("ab"))
        self.assertIsNotNone(auth.validate_username("has space"))
        self.assertIsNotNone(auth.validate_username("x" * 40))
        self.assertIsNone(auth.validate_username("ok_name-1.x"))

    def test_last_admin_cannot_be_demoted_disabled(self):
        admin = self.make("root", role="ADMIN")
        with self.assertRaises(ValueError):
            auth.set_role(admin["id"], "VIEWER")
        with self.assertRaises(ValueError):
            auth.set_active(admin["id"], False)
        second = self.make("root2", role="ADMIN")
        auth.set_role(admin["id"], "VIEWER")                      # now allowed
        self.assertEqual(auth.count_active_admins(), 1)
        with self.assertRaises(ValueError):
            auth.set_active(second["id"], False)

    def test_reset_password_unlocks_and_changes_login(self):
        u = self.make()
        for _ in range(config.MAX_FAILED_ATTEMPTS):
            auth.authenticate("bob", "badpass123")
        auth.reset_password(u["id"], "NewPass456")
        self.assertIsNone(auth.authenticate("bob", "Passw0rdX")[0])
        self.assertIsNotNone(auth.authenticate("bob", "NewPass456")[0])

    def test_role_permissions_match_documentation(self):
        p = auth.has_permission
        self.assertTrue(all(p("ADMIN", x) for x in config.PERMISSIONS["ADMIN"]))
        self.assertTrue(p("ADMIN", "admin"))
        self.assertFalse(p("ANALYST", "run_simulations"))
        self.assertTrue(p("ANALYST", "view_intel") and p("ANALYST", "download_reports"))
        self.assertTrue(p("OPERATOR", "run_simulations"))
        self.assertFalse(p("OPERATOR", "view_intel"))
        self.assertFalse(p("OPERATOR", "download_reports"))
        self.assertTrue(p("OPERATOR", "messaging"))
        self.assertTrue(p("VIEWER", "view_dashboard") and p("VIEWER", "view_sensors"))
        for perm in ("manage_events", "messaging", "view_intel", "admin", "run_simulations"):
            self.assertFalse(p("VIEWER", perm))
        self.assertFalse(p(None, "view_dashboard"))

    def test_role_change_takes_effect_on_recheck(self):
        self.make("root", role="ADMIN")
        u = self.make()
        auth.set_role(u["id"], "ANALYST")
        self.assertEqual(auth.get_active_user(u["id"])["role"], "ANALYST")

    def test_audit_trail_records_events(self):
        self.make()
        auth.authenticate("bob", "badpass123")
        auth.authenticate("bob", "Passw0rdX")
        actions = {a["action"] for a in audit.recent()}
        self.assertTrue({"USER_CREATED", "LOGIN_FAILED", "LOGIN"} <= actions)

    def test_demo_accounts_seeded_and_work(self):
        auth.seed_demo_users()
        for username, password, role, _ in config.DEMO_ACCOUNTS:
            user, err = auth.authenticate(username, password)
            self.assertEqual(err, "")
            self.assertEqual(user["role"], role)
        auth.seed_demo_users()                                     # idempotent
        self.assertEqual(len(auth.list_users()), 4)


if __name__ == "__main__":
    unittest.main()
