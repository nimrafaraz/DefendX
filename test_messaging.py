import unittest

from defendx import auth, config, db, messaging
from tests.helpers import TempDataCase


class MessagingTests(TempDataCase):
    def setUp(self):
        super().setUp()
        self.a = auth.create_user("alice", "Passw0rdA", "ADMIN")
        self.b = auth.create_user("bob", "Passw0rdB", "ANALYST")
        self.c = auth.create_user("carl", "Passw0rdC", "OPERATOR")

    def test_round_trip(self):
        messaging.send_message(self.a["id"], self.b["id"], "Hello Bob")
        messaging.send_message(self.b["id"], self.a["id"], "Hi Alice")
        conv = messaging.get_conversation(self.a["id"], self.b["id"])
        self.assertEqual([m["text"] for m in conv], ["Hello Bob", "Hi Alice"])
        self.assertTrue(all(m["ok"] for m in conv))

    def test_only_ciphertext_is_stored(self):
        messaging.send_message(self.a["id"], self.b["id"], "top secret plan")
        raw = db.query("SELECT ciphertext FROM messages")[0]["ciphertext"]
        self.assertNotIn("secret", raw)
        self.assertNotIn("top secret plan", raw)
        shown = messaging.stored_ciphertexts(self.a["id"], self.b["id"])
        self.assertEqual(shown[0]["ciphertext"], raw)

    def test_tampered_ciphertext_is_rejected(self):
        mid = messaging.send_message(self.a["id"], self.b["id"], "original")
        raw = db.query_one("SELECT ciphertext FROM messages WHERE id=?", (mid,))["ciphertext"]
        flipped = raw[:-6] + ("AAAAAA" if raw[-6:] != "AAAAAA" else "BBBBBB")
        db.execute("UPDATE messages SET ciphertext=? WHERE id=?", (flipped, mid))
        conv = messaging.get_conversation(self.a["id"], self.b["id"])
        self.assertFalse(conv[0]["ok"])
        self.assertNotIn("original", conv[0]["text"])

    def test_each_pair_has_its_own_key(self):
        k_ab = messaging.conversation_key(self.a["id"], self.b["id"])
        k_ba = messaging.conversation_key(self.b["id"], self.a["id"])
        k_ac = messaging.conversation_key(self.a["id"], self.c["id"])
        self.assertEqual(k_ab, k_ba)
        self.assertNotEqual(k_ab, k_ac)

    def test_message_for_one_pair_cannot_be_read_with_another_pairs_key(self):
        from cryptography.fernet import Fernet, InvalidToken
        messaging.send_message(self.a["id"], self.b["id"], "private")
        raw = db.query("SELECT ciphertext FROM messages")[0]["ciphertext"]
        with self.assertRaises(InvalidToken):
            Fernet(messaging.conversation_key(self.a["id"], self.c["id"])).decrypt(raw.encode())

    def test_unread_counts_and_marking_read(self):
        messaging.send_message(self.a["id"], self.b["id"], "one")
        messaging.send_message(self.a["id"], self.b["id"], "two")
        messaging.send_message(self.c["id"], self.b["id"], "three")
        self.assertEqual(messaging.unread_counts(self.b["id"]),
                         {self.a["id"]: 2, self.c["id"]: 1})
        self.assertEqual(messaging.total_unread(self.b["id"]), 3)
        conv = messaging.get_conversation(self.b["id"], self.a["id"])
        self.assertTrue(all(m["was_unread"] for m in conv))
        self.assertEqual(messaging.unread_counts(self.b["id"]), {self.c["id"]: 1})
        self.assertEqual(messaging.total_unread(self.a["id"]), 0)

    def test_sender_reading_does_not_mark_recipients_messages_read(self):
        messaging.send_message(self.a["id"], self.b["id"], "hello")
        messaging.get_conversation(self.a["id"], self.b["id"])
        self.assertEqual(messaging.total_unread(self.b["id"]), 1)

    def test_validation(self):
        with self.assertRaises(ValueError):
            messaging.send_message(self.a["id"], self.b["id"], "   ")
        with self.assertRaises(ValueError):
            messaging.send_message(self.a["id"], self.b["id"], "x" * (config.MAX_MESSAGE_LENGTH + 1))
        with self.assertRaises(ValueError):
            messaging.send_message(self.a["id"], self.a["id"], "to myself")
        with self.assertRaises(ValueError):
            messaging.send_message(self.a["id"], 9999, "nobody home")

    def test_cannot_message_disabled_user(self):
        auth.set_active(self.c["id"], False)
        with self.assertRaises(ValueError):
            messaging.send_message(self.a["id"], self.c["id"], "hi")

    def test_unicode_message(self):
        messaging.send_message(self.a["id"], self.b["id"], "Grüße ✓ مرحبا")
        self.assertEqual(messaging.get_conversation(self.b["id"], self.a["id"])[0]["text"],
                         "Grüße ✓ مرحبا")

    def test_master_key_created_reused_and_corruption_detected(self):
        self.assertFalse(config.key_path().exists())
        key1 = messaging.load_master_key()
        self.assertTrue(config.key_path().exists())
        self.assertEqual(len(key1), 32)
        self.assertEqual(messaging.load_master_key(), key1)
        config.key_path().write_text("not-a-valid-key!!")
        with self.assertRaises(ValueError):
            messaging.load_master_key()
        config.key_path().write_text("QUJD")                       # valid base64, wrong length
        with self.assertRaises(ValueError):
            messaging.load_master_key()

    def test_new_master_key_makes_old_messages_unreadable(self):
        messaging.send_message(self.a["id"], self.b["id"], "old message")
        config.key_path().unlink()                                  # simulates deleting the key
        conv = messaging.get_conversation(self.a["id"], self.b["id"])
        self.assertFalse(conv[0]["ok"])


if __name__ == "__main__":
    unittest.main()
