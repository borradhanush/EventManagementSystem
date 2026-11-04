"""Phase 15 email configuration and meeting invitation regression tests."""

import os
from unittest.mock import MagicMock, patch

from email_service import (
    EmailConfigurationError,
    send_email,
)
from test_phase12 import MeetingWorkflowTests
import app as webapp
import database


class EmailFinalizationTests(MeetingWorkflowTests):
    def test_smtp_filters_invalid_sender_and_duplicate_recipients(self):
        result = send_email(
            "Update", "Hello", ["sender@example.edu", "person@example.edu", "bad", ""],
            bcc=["PERSON@example.edu", None, "other@example.edu"],
        )
        self.assertEqual(result, {"recipient_count": 2})
        message = self.smtp.send_message.call_args.args[0]
        recipients = self.smtp.send_message.call_args.kwargs["to_addrs"]
        self.assertEqual(set(recipients), {"person@example.edu", "other@example.edu"})
        self.assertEqual(message["To"], "undisclosed-recipients:;")

    def test_invalid_or_empty_recipients_fail_safely(self):
        with self.assertRaisesRegex(ValueError, "No valid participant email recipients"):
            send_email("Update", "Hello", ["bad", "name <person@example.edu>", " "])

    def test_invalid_configured_sender_is_rejected_without_header_error(self):
        with patch.dict(os.environ, {"SENDER_EMAIL": "bad\r\nBcc: victim@example.test"}):
            with self.assertRaisesRegex(EmailConfigurationError, "SENDER_EMAIL must be a valid email address"):
                send_email("Update", "Hello", ["person@example.edu"])

    def test_smtp_uses_configured_sender_and_keeps_bcc_private_without_leaking_password(self):
        secret = "synthetic-test-app-password"
        smtp = MagicMock()
        smtp.__enter__.return_value = smtp
        smtp.__exit__.return_value = False
        with patch.dict(os.environ, {
            "SENDER_EMAIL": "sender@example.edu", "APP_PASSWORD": secret,
        }), patch("email_service.smtplib.SMTP_SSL", return_value=smtp) as smtp_factory:
            result = send_email(
                "Invitation", "Meeting information", ["sender@example.edu"],
                bcc=["person@example.edu", "PERSON@example.edu"],
            )
        self.assertEqual(result, {"recipient_count": 1})
        smtp_factory.assert_called_once_with("smtp.gmail.com", 465, timeout=20)
        smtp.login.assert_called_once_with("sender@example.edu", secret)
        message, = smtp.send_message.call_args.args
        self.assertEqual(message["From"], "sender@example.edu")
        self.assertEqual(message["To"], "undisclosed-recipients:;")
        self.assertIsNone(message["Bcc"])
        self.assertNotIn(secret, message.as_string())
        self.assertEqual(smtp.send_message.call_args.kwargs["to_addrs"], ["person@example.edu"])

    def test_event_and_program_recipient_scopes_and_current_event_team_membership(self):
        self.create_meeting(self.primary, program=self.program,
                            internal_group_types=("PROGRAM_HOSTS",), event_team_ids=(self.event_team,))
        with database.get_db() as db:
            program_meeting = db.execute("SELECT id FROM meetings ORDER BY id DESC LIMIT 1").fetchone()[0]
            second_program = self.program_row(db, self.event, "Second Program")
            second_host = self.user(db, "Second Host", "second-host@example.edu")
            db.execute("INSERT INTO program_hosts(program_id,user_id,role) VALUES (?,?,'HOST')", (second_program,second_host))
            event_cursor = db.execute(
                """INSERT INTO meetings(event_id,title,description,meeting_date,start_time,end_time,meeting_link,created_by)
                   VALUES (?,'Event-wide','', '2026-10-20','10:00','11:00','https://meet.example.test/wide',?)""",
                (self.event, self.primary),
            )
            event_meeting = event_cursor.lastrowid
            db.execute("INSERT INTO meeting_internal_group_recipients(meeting_id,event_id,group_type) VALUES (?,?,'PROGRAM_HOSTS')", (event_meeting,self.event))
            db.execute("INSERT INTO meeting_event_teams(meeting_id,event_id,event_team_id) VALUES (?,?,?)", (event_meeting,self.event,self.event_team))
            self.assertEqual(set(webapp.meeting_recipient_addresses(db, program_meeting)),
                             {"host@example.edu", "event-leader@example.edu", "event-member@example.edu"})
            self.assertEqual(set(webapp.meeting_recipient_addresses(db, event_meeting)),
                             {"host@example.edu", "second-host@example.edu", "event-leader@example.edu", "event-member@example.edu"})
            db.execute("DELETE FROM event_team_members WHERE team_id=? AND user_id=?", (self.event_team,self.event_team_member))
            self.assertEqual(set(webapp.meeting_recipient_addresses(db, event_meeting)),
                             {"host@example.edu", "second-host@example.edu", "event-leader@example.edu"})
            db.execute("UPDATE meetings SET program_id=? WHERE id=?", (second_program,program_meeting))
            self.assertEqual(set(webapp.meeting_recipient_addresses(db, program_meeting)),
                             {"second-host@example.edu", "event-leader@example.edu"})

    def test_resend_uses_smtp_and_contains_meeting_context(self):
        self.create_meeting(self.primary, program=self.program, internal_group_types=("CONVENERS",))
        with database.get_db() as db:
            meeting_id = db.execute("SELECT id FROM meetings").fetchone()[0]
        self.login_as(self.co)
        self.assertEqual(self.client.post(f"/meetings/{meeting_id}/send").status_code, 302)
        self.assertEqual(self.client.post(f"/meetings/{meeting_id}/send").status_code, 302)
        sent_messages = [call.args[0] for call in self.smtp.send_message.call_args_list]
        self.assertEqual(len(sent_messages), 2)
        for message in sent_messages:
            body = message.get_content()
            self.assertIn("Event: Event A", body)
            self.assertIn("Program: Team Program", body)
            self.assertIn("Date:", body)
            self.assertIn("Time:", body)
            self.assertIn("Join Meeting:", body)

    def test_meeting_delete_does_not_send_email(self):
        self.create_meeting(self.primary, internal_group_types=("CONVENERS",))
        with database.get_db() as db:
            meeting_id = db.execute("SELECT id FROM meetings").fetchone()[0]
        self.login_as(self.primary)
        with patch.object(webapp, "send_email") as sender:
            self.assertEqual(self.client.post(f"/meetings/{meeting_id}/delete").status_code, 302)
        sender.assert_not_called()

    def test_missing_smtp_credentials_fail_safely_without_secret_exposure(self):
        secret = "synthetic-missing-config-secret"
        with patch.dict(os.environ, {"APP_PASSWORD": secret}, clear=False):
            os.environ.pop("SENDER_EMAIL", None)
            with self.assertRaises(EmailConfigurationError) as error:
                send_email("Update", "Hello", ["person@example.edu"])
        self.assertIn("SENDER_EMAIL", str(error.exception))
        self.assertNotIn(secret, str(error.exception))
        self.smtp.login.assert_not_called()


if __name__ == "__main__":
    import unittest
    unittest.main()
