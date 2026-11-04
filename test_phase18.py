"""Registration OTP, email delivery, and profile completion tests."""

import contextlib
import io
import os
import re
import sqlite3
import smtplib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import app as webapp
import database
import email_service


class EmailVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DATABASE_PATH = Path(self.temp_dir.name) / "phase18.db"
        database.init_db()
        self.original_email_env = {name: os.environ.get(name) for name in ("SENDER_EMAIL", "APP_PASSWORD")}
        os.environ.update(SENDER_EMAIL="sender@example.test", APP_PASSWORD="synthetic-test-app-password")
        self.smtp = MagicMock()
        self.smtp.__enter__.return_value = self.smtp
        self.smtp.__exit__.return_value = False
        smtp_patcher = patch("email_service.smtplib.SMTP_SSL", return_value=self.smtp)
        smtp_patcher.start()
        self.addCleanup(smtp_patcher.stop)
        webapp.app.config.update(TESTING=True, SECRET_KEY="phase18-fixed-test-secret")
        self.client = webapp.app.test_client()

    def tearDown(self):
        for name, value in self.original_email_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self.temp_dir.cleanup()

    def register(self, email="new@phase18.test"):
        return self.client.post("/register", data={
            "full_name": "New Participant", "email": email, "password": "correct-horse-934",
            # Old extra fields are ignored; profile details are collected after login.
            "phone": "must-not-be-used", "institution": "Must Not Be Used", "affiliation": "external",
        })

    def sent_messages(self):
        return [call.args[0] for call in self.smtp.send_message.call_args_list]

    def code_from_email(self, index=-1):
        message = self.sent_messages()[index]
        match = re.search(r"(?<!\d)(\d{6})(?!\d)", message.get_content())
        if not match:
            raise AssertionError("Mock verification email did not contain a six-digit code")
        return match.group(1)

    def user(self, email="new@phase18.test"):
        with database.get_db() as db:
            return db.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()

    def pending(self, email="new@phase18.test"):
        with database.get_db() as db:
            return db.execute("SELECT * FROM pending_registrations WHERE email=? COLLATE NOCASE", (email,)).fetchone()

    def otp(self, pending_id):
        with database.get_db() as db:
            return db.execute("SELECT * FROM pending_registration_otps WHERE pending_registration_id=? ORDER BY id DESC LIMIT 1", (pending_id,)).fetchone()

    def verify(self, code=None):
        return self.client.post("/verify-email", data={"otp": code or self.code_from_email()})

    def test_smtp_recipient_hmac_storage_and_no_account_until_correct_otp(self):
        response = self.register()
        self.assertEqual(response.location, "/verify-email")
        self.assertIsNone(self.user())
        pending = self.pending()
        self.assertIsNotNone(pending)
        messages = self.sent_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(self.smtp.send_message.call_args.kwargs["to_addrs"], ["new@phase18.test"])
        self.assertEqual(messages[0]["Subject"], "Verify your email")
        code = self.code_from_email()
        self.assertNotIn(code.encode(), response.data)
        row = self.otp(pending["id"])
        self.assertNotEqual(row["otp_hash"], code)
        self.assertNotIn(code, row["otp_hash"])
        self.assertNotIn(code, self.client.get("/verify-email").get_data(as_text=True))
        self.assertEqual(self.verify(code).location, "/login")
        user = self.user()
        self.assertEqual(user["email_verified"], 1)
        self.assertEqual(user["profile_completed"], 0)
        self.assertEqual((user["phone"], user["institution"]), ("", ""))
        self.assertEqual(self.client.post("/login", data={"email": "new@phase18.test", "password": "correct-horse-934"}).location, "/dashboard")
        self.assertEqual(self.client.post("/logout").status_code, 302)

    def test_registration_form_has_only_account_creation_fields(self):
        page = self.client.get("/register").get_data(as_text=True)
        for field in ("full_name", "email", "password"):
            self.assertIn(f'name="{field}"', page)
        for field in ("phone", "institution", "affiliation"):
            self.assertNotIn(f'name="{field}"', page)

    def test_dotenv_loader_loads_missing_values_without_overriding_os_values(self):
        from unittest.mock import patch as env_patch
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("SYNTHETIC_CONFIG_VALUE=file-value\nSYNTHETIC_OS_VALUE=file-value\n", encoding="utf-8")
            with env_patch.dict(os.environ, {"SYNTHETIC_OS_VALUE": "os-value"}, clear=False):
                os.environ.pop("SYNTHETIC_CONFIG_VALUE", None)
                webapp.load_application_environment(env_file)
                self.assertEqual(os.environ["SYNTHETIC_CONFIG_VALUE"], "file-value")
                self.assertEqual(os.environ["SYNTHETIC_OS_VALUE"], "os-value")
                os.environ.pop("SYNTHETIC_CONFIG_VALUE", None)

    def test_wrong_expired_attempt_limited_and_resend_challenges(self):
        self.register()
        pending_id = self.pending()["id"]
        for count in range(1, 6):
            self.client.post("/verify-email", data={"otp": "999999"})
            self.assertEqual(self.otp(pending_id)["attempt_count"], count)
        self.assertIsNotNone(self.otp(pending_id)["invalidated_at"])
        self.assertIsNone(self.user())
        with database.get_db() as db:
            db.execute("UPDATE pending_registration_otps SET created_at=datetime('now','-61 seconds') WHERE pending_registration_id=?", (pending_id,))
        self.client.post("/verify-email/resend")
        self.assertEqual(len(self.sent_messages()), 2)
        self.assertEqual(self.verify(self.code_from_email()).location, "/login")

    def test_verification_is_session_bound_ignores_posted_registration_id_and_masks_email(self):
        self.register("participant.long@phase18.test")
        pending_id = self.pending("participant.long@phase18.test")["id"]
        code = self.code_from_email()
        page = self.client.get("/verify-email").get_data(as_text=True)
        self.assertIn("p*******@phase18.test", page)
        with self.client.session_transaction() as session:
            session.pop(webapp.PENDING_REGISTRATION_SESSION_KEY, None)
        response = self.client.post("/verify-email", data={"otp": code, "pending_registration_id": pending_id})
        self.assertEqual(response.location, "/register")
        self.assertIsNone(self.user("participant.long@phase18.test"))

    def test_resend_cooldown_hourly_limit_and_previous_code_invalidation(self):
        self.register()
        pending_id = self.pending()["id"]
        old_code = self.code_from_email()
        self.client.post("/verify-email/resend")
        self.assertEqual(len(self.sent_messages()), 1)
        with database.get_db() as db:
            db.execute("UPDATE pending_registration_otps SET created_at=datetime('now','-61 seconds') WHERE pending_registration_id=?", (pending_id,))
        self.client.post("/verify-email/resend")
        new_code = self.code_from_email()
        self.assertNotEqual(old_code, new_code)
        self.assertEqual(self.client.post("/verify-email", data={"otp": old_code}).status_code, 200)
        for _ in range(3):
            with database.get_db() as db:
                db.execute("UPDATE pending_registration_otps SET created_at=datetime('now','-61 seconds') WHERE pending_registration_id=?", (pending_id,))
            self.client.post("/verify-email/resend")
        self.assertEqual(len(self.sent_messages()), 5)
        with database.get_db() as db:
            db.execute("UPDATE pending_registration_otps SET created_at=datetime('now','-61 seconds') WHERE pending_registration_id=?", (pending_id,))
        blocked = self.client.post("/verify-email/resend")
        self.assertEqual(len(self.sent_messages()), 5)
        self.assertEqual(blocked.location, "/verify-email")
        self.assertIn(b"Too many verification emails", self.client.get("/verify-email").data)
        self.assertEqual(self.verify(self.code_from_email()).location, "/login")

    def test_legacy_unverified_account_can_still_complete_existing_otp_flow(self):
        with database.get_db() as db:
            cursor = db.execute("INSERT INTO users(full_name,email,password_hash,affiliation,email_verified) VALUES('Legacy User','legacy@phase18.test','hash','internal',0)")
            user_id = cursor.lastrowid
        with self.client.session_transaction() as session:
            session[webapp.EMAIL_VERIFICATION_SESSION_KEY] = user_id
        sent, _ = webapp.send_verification_otp(user_id, "Legacy User", "legacy@phase18.test")
        self.assertTrue(sent)
        code = self.code_from_email()
        self.assertEqual(self.verify(code).location, "/login")
        with database.get_db() as db:
            self.assertEqual(db.execute("SELECT email_verified FROM users WHERE id=?", (user_id,)).fetchone()[0], 1)

    def test_expired_code_is_rejected(self):
        self.register()
        pending_id = self.pending()["id"]
        with database.get_db() as db:
            db.execute("UPDATE pending_registration_otps SET expires_at='2000-01-01 00:00:00' WHERE pending_registration_id=?", (pending_id,))
        self.verify()
        self.assertIsNone(self.user())
        self.assertIsNotNone(self.otp(pending_id)["invalidated_at"])

    def test_duplicate_registration_and_existing_account_protection(self):
        self.register()
        original = self.pending()
        response = self.register("NEW@phase18.test")
        self.assertEqual(response.location, "/verify-email")
        self.assertEqual(self.pending()["id"], original["id"])
        self.assertEqual(len(self.sent_messages()), 2)
        self.verify()
        response = self.register("NEW@phase18.test")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"already exists", response.data)

    def test_email_failure_creates_no_user_and_error_is_safe_and_retryable(self):
        with patch("email_service.smtplib.SMTP_SSL", side_effect=smtplib.SMTPException("synthetic delivery failure")):
            response = self.register()
        self.assertEqual(response.location, "/verify-email")
        self.assertIsNone(self.user())
        self.assertIsNotNone(self.pending())
        page = self.client.get("/verify-email").data
        self.assertIn(b"could not send", page)
        self.assertNotIn(b"smtp password", response.data + page)
        self.assertNotIn(b"secret", response.data + page)
        self.assertIsNotNone(self.otp(self.pending()["id"])["invalidated_at"])
        with database.get_db() as db:
            db.execute("UPDATE pending_registration_otps SET created_at=datetime('now','-61 seconds') WHERE pending_registration_id=?", (self.pending()["id"],))
        self.assertEqual(self.client.post("/verify-email/resend").location, "/verify-email")

    def test_otp_not_printed_or_logged(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.register()
        code = self.code_from_email()
        self.assertNotIn(code, stdout.getvalue())
        self.assertNotIn(code, stderr.getvalue())

    def test_smtp_configuration_failure_is_safe_without_network(self):
        os.environ.pop("SENDER_EMAIL", None)
        os.environ.pop("APP_PASSWORD", None)
        with patch.object(email_service.smtplib, "SMTP_SSL") as smtp:
            response = self.register()
        smtp.assert_not_called()
        self.assertIsNone(self.user())
        self.assertNotIn(b"APP_PASSWORD", self.client.get("/verify-email").data)
        self.assertNotIn(b"Traceback", response.data)

    def test_profile_completion_required_before_program_registration(self):
        self.register()
        self.verify()
        self.client.post("/login", data={"email": "new@phase18.test", "password": "correct-horse-934"})
        profile = self.client.get("/profile").get_data(as_text=True)
        self.assertIn("Complete your phone and institute/university details", profile)
        with database.get_db() as db:
            # An otherwise eligible program is enough to verify that gating occurs before resource lookup.
            program_id = 987654
        response = self.client.get(f"/programs/{program_id}/register")
        self.assertEqual(response.location, "/profile")
        response = self.client.post("/profile", data={"full_name": "New Participant", "phone": "5550100", "institution": "Example College", "affiliation": "external"})
        self.assertEqual(response.location, "/profile")
        self.assertEqual(self.user()["profile_completed"], 1)
        self.assertEqual(self.client.get(f"/programs/{program_id}/register").status_code, 404)

    def test_missing_fields_invalid_email_and_legacy_user_migration(self):
        response = self.register("not-an-email")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"valid email", response.data)
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        old_path = database.DATABASE_PATH
        try:
            database.DATABASE_PATH = legacy_path
            legacy_db = sqlite3.connect(legacy_path)
            with legacy_db as db:
                db.execute("""CREATE TABLE users(id INTEGER PRIMARY KEY,full_name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,phone TEXT DEFAULT '',institution TEXT DEFAULT '',affiliation TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',face_image TEXT DEFAULT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
                db.execute("INSERT INTO users(full_name,email,password_hash,affiliation) VALUES('Legacy','old@phase18.test','hash','internal')")
            legacy_db.close()
            database.init_db()
            with database.get_db() as db:
                row = db.execute("SELECT email_verified,profile_completed FROM users WHERE email='old@phase18.test'").fetchone()
                self.assertEqual((row["email_verified"], row["profile_completed"]), (1, 1))
        finally:
            database.DATABASE_PATH = old_path


if __name__ == "__main__":
    unittest.main()
