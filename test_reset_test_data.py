"""Safety tests for the manual SQLite test-data reset utility."""

import contextlib
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as webapp
import database
import reset_test_data


class ResetTestDataTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "reset-test.db"
        self.original_db_path = database.DATABASE_PATH
        database.DATABASE_PATH = self.db_path
        database.init_db()
        with database.get_db() as db:
            self.user_id = db.execute(
                "INSERT INTO users(full_name,email,password_hash,affiliation) VALUES('Test User','reset@example.test','hash','internal')"
            ).lastrowid
            self.request_id = db.execute(
                "INSERT INTO event_requests(requester_id,event_title,description,proposed_date,venue) VALUES(?,'Test Event','Details','2035-01-01','Hall')",
                (self.user_id,),
            ).lastrowid
            db.execute(
                "INSERT INTO event_request_history(event_request_id,actor_id,action,event_title,description,proposed_date,venue) VALUES(?,?,'submitted','Test Event','Details','2035-01-01','Hall')",
                (self.request_id, self.user_id),
            )

    def tearDown(self):
        database.DATABASE_PATH = self.original_db_path
        self.temp_dir.cleanup()

    def app_tables(self, connection):
        return [
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            if reset_test_data._is_application_table(row[0])
        ]

    def schema_snapshot(self):
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            return db.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()

    def test_reset_clears_all_tables_and_preserves_schema_indexes_constraints_and_sequence(self):
        schema_before = self.schema_snapshot()
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            tables_before = self.app_tables(db)
            self.assertGreaterEqual(len(tables_before), 20)
            self.assertGreater(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

        cleared = reset_test_data.reset_application_data(self.db_path)
        self.assertEqual(set(cleared), set(tables_before))
        self.assertGreaterEqual(cleared["users"], 1)
        self.assertGreaterEqual(cleared["event_requests"], 1)
        self.assertGreaterEqual(cleared["event_request_history"], 1)
        self.assertEqual(self.schema_snapshot(), schema_before)

        # Re-run the normal, idempotent initializer and ensure Flask still
        # serves its unauthenticated pages using the reset database.
        database.init_db()
        client = webapp.app.test_client()
        self.assertEqual(client.get("/login").status_code, 200)
        self.assertEqual(client.get("/events").status_code, 200)

        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertTrue(all(db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0] == 0 for name in tables_before))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            next_user = db.execute(
                "INSERT INTO users(full_name,email,password_hash,affiliation) VALUES('Fresh','fresh@example.test','hash','internal')"
            ).lastrowid
            self.assertEqual(next_user, 1)

    def test_confirmation_other_than_exact_reset_cancels_without_changes(self):
        before = self.schema_snapshot()
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            count_before = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        output = io.StringIO()
        with patch.object(reset_test_data, "DATABASE_PATH", self.db_path), patch("builtins.input", return_value="reset"), contextlib.redirect_stdout(output):
            result = reset_test_data.main()
        self.assertEqual(result, 0)
        self.assertIn("cancelled", output.getvalue().lower())
        self.assertEqual(self.schema_snapshot(), before)
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], count_before)

    def test_exact_reset_confirmation_runs_utility_and_prints_summary(self):
        output = io.StringIO()
        with patch.object(reset_test_data, "DATABASE_PATH", self.db_path), patch("builtins.input", return_value="RESET"), contextlib.redirect_stdout(output):
            result = reset_test_data.main()
        self.assertEqual(result, 0)
        self.assertIn("Reset complete", output.getvalue())
        self.assertIn("event_request_history", output.getvalue())
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM event_requests").fetchone()[0], 0)

    def test_failure_rolls_back_prior_deletes(self):
        with database.get_db() as db:
            db.execute(
                "CREATE TRIGGER reject_user_reset BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'test failure'); END"
            )
        error_output = io.StringIO()
        with patch.object(reset_test_data, "DATABASE_PATH", self.db_path), patch("builtins.input", return_value="RESET"), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(error_output):
            result = reset_test_data.main()
        self.assertEqual(result, 1)
        self.assertIn("transaction was rolled back", error_output.getvalue())
        with contextlib.closing(sqlite3.connect(self.db_path)) as db:
            self.assertGreater(db.execute("SELECT COUNT(*) FROM event_requests").fetchone()[0], 0)
            self.assertGreater(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])


if __name__ == "__main__":
    unittest.main()
