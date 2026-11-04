"""Final security checks for sessions, malformed inputs, privacy and isolation."""

import sqlite3
import tempfile
import unittest
import os
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

from werkzeug.security import check_password_hash

import app as webapp
import database


class FinalSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DATABASE_PATH = Path(self.temp_dir.name) / "phase17_security.db"
        database.init_db()
        webapp.app.config.update(TESTING=True, SECRET_KEY="phase17-test-key")
        self.client = webapp.app.test_client()
        with database.get_db() as db:
            self.user_id = self.add_user(db, "Participant", "participant@p17.test")
            self.other_id = self.add_user(db, "Other User", "other@p17.test")
            self.root_id = self.add_user(db, "Root", "root@p17.test", "root")
            self.event_id = self.add_event(db, self.user_id, "Public Security Event", "PUBLIC")
            self.private_event_id = self.add_event(db, self.other_id, "Private Security Event", "PRIVATE")

    def tearDown(self):
        self.temp_dir.cleanup()

    @staticmethod
    def add_user(db, name, email, role="user"):
        return db.execute(
            "INSERT INTO users(full_name,email,password_hash,affiliation,role,email_verified) VALUES(?,?,?,'internal',?,1)",
            (name, email, "placeholder-hash", role),
        ).lastrowid

    @staticmethod
    def add_event(db, owner_id, name, visibility):
        request_id = db.execute(
            "INSERT INTO event_requests(requester_id,event_title,description,proposed_date,venue) VALUES(?,?,'Details','2032-05-01','Hall')",
            (owner_id, name),
        ).lastrowid
        return db.execute(
            """INSERT INTO events(event_request_id,event_name,start_date,end_date,venue,visibility,primary_convener_id)
               VALUES(?,?, '2032-05-01','2032-05-02','Hall',?,?)""",
            (request_id, name, visibility, owner_id),
        ).lastrowid

    def login(self, user_id, role="user"):
        with self.client.session_transaction() as session:
            session["user_id"] = user_id
            session["role"] = role

    def test_registration_keeps_password_hashed_and_creates_user_only_after_otp(self):
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = False
        with patch.dict(os.environ, {"SENDER_EMAIL": "sender@example.test", "APP_PASSWORD": "synthetic-test-app-password"}, clear=False), \
             patch("email_service.smtplib.SMTP_SSL", return_value=smtp):
            response = self.client.post("/register", data={
                "full_name": "New User", "email": "new@p17.test", "password": "correct-horse-934",
                "phone": "555", "institution": "College", "affiliation": "internal",
            })
        self.assertEqual(response.status_code, 302)
        with database.get_db() as db:
            row = db.execute("SELECT password_hash FROM pending_registrations WHERE email='new@p17.test'").fetchone()
            user = db.execute("SELECT id FROM users WHERE email='new@p17.test'").fetchone()
        self.assertIsNotNone(row)
        self.assertIsNone(user)
        self.assertNotEqual(row["password_hash"], "correct-horse-934")
        self.assertTrue(check_password_hash(row["password_hash"], "correct-horse-934"))
        self.assertNotIn(b"correct-horse-934", response.data)
        message = smtp.send_message.call_args.args[0]
        code = re.search(r"(?<!\d)(\d{6})(?!\d)", message.get_content()).group(1)
        self.assertEqual(message["To"], "undisclosed-recipients:;")
        self.assertEqual(smtp.send_message.call_args.kwargs["to_addrs"], ["new@p17.test"])
        with patch.dict(os.environ, {"SENDER_EMAIL": "sender@example.test", "APP_PASSWORD": "synthetic-test-app-password"}, clear=False):
            self.assertEqual(self.client.post("/verify-email", data={"otp": code}).location, "/login")
        with database.get_db() as db:
            self.assertIsNotNone(db.execute("SELECT id FROM users WHERE email='new@p17.test' AND email_verified=1").fetchone())

    def test_login_cookie_and_authenticated_pages_have_cache_protection(self):
        with database.get_db() as db:
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (webapp.generate_password_hash("long-test-pass"), self.user_id))
        response = self.client.post("/login", data={"email": "participant@p17.test", "password": "long-test-pass"})
        cookie = response.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertIn("no-store", response.headers.get("Cache-Control", ""))
        protected = self.client.get("/dashboard")
        self.assertEqual(protected.status_code, 200)
        self.assertIn("no-store", protected.headers.get("Cache-Control", ""))
        self.assertIn("no-cache", protected.headers.get("Cache-Control", ""))
        self.assertEqual(protected.headers.get("Pragma"), "no-cache")

    def test_logout_clears_session_and_protected_pages_require_reauthentication(self):
        self.login(self.user_id)
        before_logout = self.client.get("/profile")
        self.assertEqual(before_logout.status_code, 200)
        self.assertIn("no-store", before_logout.headers.get("Cache-Control", ""))
        logout = self.client.post("/logout")
        self.assertEqual(logout.status_code, 302)
        self.assertIn("no-store", logout.headers.get("Cache-Control", ""))
        self.assertEqual(self.client.get("/profile").status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_invalid_stale_session_is_cleared_without_server_error(self):
        self.login(987654321)
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_face_endpoints_reject_malformed_json_with_safe_response(self):
        self.login(self.user_id)
        for body in ([], {"image_data": ["not", "text"]}, {"image_data": "data:image/jpeg;base64,***"}):
            response = self.client.post("/face-registration", json=body)
            self.assertEqual(response.status_code, 400)
            self.assertIn(b"Invalid", response.data)
            self.assertNotIn(b"Traceback", response.data)
        verification = self.client.post("/face-verification", json=[])
        self.assertEqual(verification.status_code, 400)
        self.assertNotIn(b"Traceback", verification.data)

    def test_private_event_is_not_exposed_by_listing_or_public_detail(self):
        listing = self.client.get("/events")
        self.assertEqual(listing.status_code, 200)
        self.assertIn(b"Public Security Event", listing.data)
        self.assertNotIn(b"Private Security Event", listing.data)
        self.assertEqual(self.client.get(f"/events/{self.event_id}").status_code, 200)
        self.assertEqual(self.client.get(f"/events/{self.private_event_id}").status_code, 404)

    def test_database_foreign_keys_are_enabled_and_enforced(self):
        with database.get_db() as db:
            self.assertEqual(db.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO event_co_conveners(event_id,user_id) VALUES(999999,?)", (self.other_id,))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])


if __name__ == "__main__":
    unittest.main()
