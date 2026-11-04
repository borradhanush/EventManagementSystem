import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import database
import app as webapp
from email_service import EmailConfigurationError, send_email


class MeetingWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DATABASE_PATH = Path(self.temp_dir.name) / "meetings_test.db"
        database.init_db()
        webapp.app.config.update(TESTING=True, SECRET_KEY="meeting-tests")
        self.client = webapp.app.test_client()
        self.old_env = {key: os.environ.get(key) for key in ("SENDER_EMAIL", "APP_PASSWORD")}
        os.environ["SENDER_EMAIL"] = "sender@example.edu"
        os.environ["APP_PASSWORD"] = "synthetic-test-app-password"
        self.smtp = MagicMock()
        self.smtp.__enter__.return_value = self.smtp
        self.smtp.__exit__.return_value = False
        smtp_patcher = patch("email_service.smtplib.SMTP_SSL", return_value=self.smtp)
        smtp_patcher.start()
        self.addCleanup(smtp_patcher.stop)
        with database.get_db() as db:
            self.primary = self.user(db, "Primary", "primary@example.edu")
            self.co = self.user(db, "Co", "co@example.edu")
            self.participant = self.user(db, "Participant", "participant@example.edu")
            self.team_mate = self.user(db, "Team Mate", "mate@example.edu")
            self.gate_staff = self.user(db, "Gate Staff", "gate@example.edu")
            self.accommodation_staff = self.user(db, "Accommodation Staff", "accommodation@example.edu")
            self.event_team_leader = self.user(db, "Event Team Leader", "event-leader@example.edu")
            self.event_team_member = self.user(db, "Event Team Member", "event-member@example.edu")
            self.program_host = self.user(db, "Program Host", "host@example.edu")
            self.unrelated = self.user(db, "Unrelated", "unrelated@example.edu")
            self.root = self.user(db, "Root", "root@example.edu", "root")
            request_id = db.execute(
                """INSERT INTO event_requests(requester_id,event_title,description,proposed_date,venue)
                   VALUES (?, 'Event A', '', '2026-11-01', 'Hall')""", (self.primary,)
            ).lastrowid
            self.event = db.execute(
                """INSERT INTO events(event_request_id,event_name,start_date,end_date,primary_convener_id)
                   VALUES (?, 'Event A', '2026-11-01','2026-11-02',?)""", (request_id, self.primary)
            ).lastrowid
            db.execute("INSERT INTO event_co_conveners(event_id,user_id) VALUES (?,?)", (self.event, self.co))
            db.execute("INSERT INTO event_gate_staff(event_id,user_id) VALUES (?,?)", (self.event, self.gate_staff))
            db.execute("INSERT INTO event_accommodation_team(event_id,user_id) VALUES (?,?)", (self.event, self.accommodation_staff))
            self.event_team = db.execute(
                "INSERT INTO event_teams(event_id,team_name,description,team_leader_id) VALUES (?,?,?,?)",
                (self.event, "Operations", "Internal operations group", self.event_team_leader),
            ).lastrowid
            db.execute("INSERT INTO event_team_members(team_id,user_id) VALUES (?,?)", (self.event_team,self.event_team_member))
            second_req = db.execute(
                """INSERT INTO event_requests(requester_id,event_title,description,proposed_date,venue)
                   VALUES (?, 'Event B', '', '2026-11-01', 'Hall')""", (self.unrelated,)
            ).lastrowid
            self.event_b = db.execute(
                """INSERT INTO events(event_request_id,event_name,start_date,end_date,primary_convener_id)
                   VALUES (?, 'Event B', '2026-11-01','2026-11-02',?)""", (second_req, self.unrelated)
            ).lastrowid
            self.program = self.program_row(db, self.event, "Team Program")
            db.execute("INSERT INTO program_hosts(program_id,user_id,role) VALUES (?,?,'HOST')", (self.program,self.program_host))
            self.other_program = self.program_row(db, self.event_b, "Other Program")
            self.reg = self.registration(db, self.event, self.program, self.participant)
            self.reg2 = self.registration(db, self.event, self.program, self.team_mate)
            unrelated_registration = self.registration(db, self.event, self.program, self.unrelated)
            self.team = db.execute(
                """INSERT INTO participant_teams(program_id,event_id,creator_registration_id,captain_registration_id)
                   VALUES (?,?,?,?)""", (self.program, self.event, self.reg, self.reg)
            ).lastrowid
            db.executemany(
                "INSERT INTO participant_team_members(team_id,program_id,event_id,registration_id) VALUES (?,?,?,?)",
                [(self.team,self.program,self.event,self.reg),(self.team,self.program,self.event,self.reg2)],
            )
            self.unselected_reg = unrelated_registration

    def tearDown(self):
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temp_dir.cleanup()

    @staticmethod
    def user(db, name, email, role="user"):
        return db.execute(
            "INSERT INTO users(full_name,email,password_hash,affiliation,role) VALUES (?,?,?,'internal',?)",
            (name,email,"test-hash",role),
        ).lastrowid

    @staticmethod
    def program_row(db, event_id, name):
        return db.execute(
            """INSERT INTO programs(event_id,program_name,category,participation_mode,team_size,start_at,end_at,
                 registration_deadline,venue) VALUES (?,?,'Contest','TEAM',3,'2026-11-01T10:00',
                 '2026-11-01T12:00','2026-10-31T23:59','Hall')""", (event_id,name)
        ).lastrowid

    @staticmethod
    def registration(db, event_id, program_id, user_id):
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return db.execute(
            """INSERT INTO participant_registrations(event_id,program_id,user_id,participant_type,full_name,email,
                 registration_mode) VALUES (?,?,?,'OUTSIDER',?,?,'TEAM')""",
            (event_id,program_id,user_id,user["full_name"],user["email"]),
        ).lastrowid

    def login_as(self, user_id, role="user"):
        with self.client.session_transaction() as session:
            session["user_id"] = user_id
            session["role"] = role

    def meeting_form(self, program=None, internal_group_types=(), event_team_ids=()):
        data = {"title":"Team Meeting", "description":"Plan the event.", "meeting_date":"2026-10-20",
                "start_time":"10:00", "end_time":"11:00", "meeting_link":"https://meet.example.test/room"}
        if program is not None:
            data["program_id"] = str(program)
        data["internal_group_types"] = list(internal_group_types)
        data["event_team_ids"] = [str(value) for value in event_team_ids]
        return data

    def create_meeting(self, who, **kwargs):
        self.login_as(who)
        return self.client.post(f"/convener/events/{self.event}/meetings/new", data=self.meeting_form(**kwargs))

    def test_primary_and_co_convener_can_create_edit_and_delete(self):
        for user_id in (self.primary, self.co):
            self.assertEqual(self.create_meeting(user_id, program=self.program, internal_group_types=("CONVENERS",)).status_code, 302)
        with database.get_db() as db:
            meeting_id = db.execute("SELECT id FROM meetings ORDER BY id LIMIT 1").fetchone()[0]
        self.login_as(self.primary)
        self.assertEqual(self.client.post(f"/meetings/{meeting_id}/edit", data=self.meeting_form(program=self.program, internal_group_types=("GATE_STAFF",), event_team_ids=(self.event_team,))).status_code, 302)
        self.assertEqual(self.client.post(f"/meetings/{meeting_id}/delete").status_code, 302)

    def test_event_level_meeting_and_management_views_render(self):
        self.login_as(self.primary)
        self.assertEqual(self.client.get(f"/convener/events/{self.event}/meetings/new").status_code, 200)
        self.assertEqual(self.client.post(f"/convener/events/{self.event}/meetings/new", data=self.meeting_form()).status_code, 302)
        self.assertEqual(self.client.get(f"/convener/events/{self.event}/meetings").status_code, 200)
        with database.get_db() as db:
            self.assertIsNone(db.execute("SELECT program_id FROM meetings").fetchone()[0])

    def test_unauthorized_root_and_program_host_cannot_manage(self):
        self.login_as(self.unrelated)
        self.assertEqual(self.client.get(f"/convener/events/{self.event}/meetings").status_code, 403)
        self.login_as(self.root, "root")
        self.assertEqual(self.client.get(f"/convener/events/{self.event}/meetings").status_code, 403)
        with database.get_db() as db:
            db.execute("INSERT INTO program_hosts(program_id,user_id,role) VALUES (?,?,'CO_HOST')", (self.program,self.unrelated))
        self.login_as(self.unrelated)
        self.assertEqual(self.client.get(f"/convener/events/{self.event}/meetings").status_code, 403)

    def test_program_scope_and_cross_event_rejected(self):
        self.login_as(self.primary)
        self.assertEqual(self.client.post(f"/convener/events/{self.event}/meetings/new", data=self.meeting_form(program=self.program)).status_code, 302)
        bad = self.client.post(f"/convener/events/{self.event}/meetings/new", data=self.meeting_form(program=self.other_program))
        self.assertEqual(bad.status_code, 200)
        self.assertIn(b"does not belong to this event", bad.data)

    def test_participant_access_and_read_only_rules(self):
        self.assertEqual(self.create_meeting(self.primary, program=self.program, internal_group_types=("CONVENERS",), event_team_ids=(self.event_team,)).status_code, 302)
        with database.get_db() as db:
            meeting_id = db.execute("SELECT id FROM meetings").fetchone()[0]
        self.login_as(self.participant)
        self.assertEqual(self.client.get(f"/meetings/{meeting_id}").status_code, 403)
        self.login_as(self.team_mate)
        self.assertEqual(self.client.get(f"/meetings/{meeting_id}").status_code, 403)
        self.login_as(self.unrelated)
        self.assertEqual(self.client.get(f"/meetings/{meeting_id}").status_code, 403)
        self.assertEqual(self.client.post(f"/meetings/{meeting_id}/delete").status_code, 403)
        self.login_as(self.root, "root")
        self.assertEqual(self.client.get(f"/meetings/{meeting_id}").status_code, 403)

    def test_recipient_resolution_smtp_and_bcc_privacy(self):
        self.create_meeting(self.primary, program=self.program,
                            internal_group_types=("CONVENERS", "GATE_STAFF", "ACCOMMODATION_TEAM", "PROGRAM_HOSTS"),
                            event_team_ids=(self.event_team,))
        with database.get_db() as db:
            meeting_id = db.execute("SELECT id FROM meetings").fetchone()[0]
        self.login_as(self.co)
        self.assertEqual(self.client.post(f"/meetings/{meeting_id}/send").status_code, 302)
        message, = self.smtp.send_message.call_args.args
        recipients = self.smtp.send_message.call_args.kwargs["to_addrs"]
        self.assertEqual(set(recipients), {"primary@example.edu", "co@example.edu", "gate@example.edu", "accommodation@example.edu",
                                           "host@example.edu", "event-leader@example.edu", "event-member@example.edu"})
        self.assertEqual(message["To"], "undisclosed-recipients:;")
        self.assertIsNone(message["Bcc"])
        self.assertNotIn("sender@example.edu", recipients)
        self.assertNotIn("participant@example.edu", recipients)
        self.assertIn("Join Meeting:", message.get_content())

    def test_smtp_missing_configuration_is_safe(self):
        os.environ.pop("SENDER_EMAIL", None)
        with self.assertRaises(EmailConfigurationError) as error:
            send_email("Test", "Body", ["person@example.edu"])
        self.assertNotIn("synthetic-test-app-password", str(error.exception))
        self.assertIn("SENDER_EMAIL", str(error.exception))

    def test_no_group_or_team_is_required_to_create_but_sending_requires_recipients(self):
        self.assertEqual(self.create_meeting(self.primary).status_code, 302)
        with database.get_db() as db:
            meeting_id = db.execute("SELECT id FROM meetings").fetchone()[0]
            self.assertEqual(webapp.meeting_recipient_addresses(db, meeting_id), [])
        self.login_as(self.primary)
        self.assertEqual(self.client.post(f"/meetings/{meeting_id}/send").status_code, 302)

    def test_recipient_selection_rejects_groups_or_event_teams_from_another_event(self):
        self.login_as(self.primary)
        bad_group = self.client.post(f"/convener/events/{self.event}/meetings/new",
                                     data=self.meeting_form(internal_group_types=("NOT_A_GROUP",)))
        self.assertIn(b"Choose an internal group assigned to this event", bad_group.data)
        with database.get_db() as db:
            other_team = db.execute(
                "INSERT INTO event_teams(event_id,team_name,description,team_leader_id) VALUES (?,?,?,?)",
                (self.event_b, "Other Operations", "", self.unrelated),
            ).lastrowid
        bad_team = self.client.post(f"/convener/events/{self.event}/meetings/new",
                                    data=self.meeting_form(event_team_ids=(other_team,)))
        self.assertIn(b"Event management teams must belong to this event", bad_team.data)


if __name__ == "__main__":
    unittest.main()
