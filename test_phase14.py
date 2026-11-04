import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from urllib.request import urlopen

from werkzeug.serving import make_server

import app as webapp
import database


class ParticipantDashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DATABASE_PATH = Path(self.temp_dir.name) / "participant_dashboard.db"
        database.init_db()
        webapp.app.config.update(TESTING=True,SECRET_KEY="phase14-tests")
        self.users={}
        self.clients={}
        with database.get_db() as db:
            people=[("Primary","primary@p14.test","user"),("CoConvener","co@p14.test","user"),
                    ("Participant One","one@p14.test","user"),("Participant Two","two@p14.test","user"),
                    ("Unrelated","unrelated@p14.test","user"),("Event Team Leader","leader@p14.test","user"),
                    ("Gate Staff","gate@p14.test","user"),("Accommodation Staff","accom@p14.test","user"),
                    ("Program Host","host@p14.test","user"),("Root","root@p14.test","root")]
            for name,email,role in people:
                self.users[name]=db.execute(
                    """INSERT INTO users(full_name,email,password_hash,phone,institution,affiliation,role,face_embedding)
                       VALUES(?,?,?,'555-1234','Stored University','internal',?,'face-embedding-private')""",
                    (name,email,"password-hash-private",role),
                ).lastrowid
            self.event=self.make_event(db,self.users["Primary"],"Participant Event")
            self.other_event=self.make_event(db,self.users["Unrelated"],"Unrelated Event")
            db.execute("INSERT INTO event_co_conveners(event_id,user_id) VALUES(?,?)",(self.event,self.users["CoConvener"]))
            self.team_program=self.make_program(db,self.event,"Team Program","TEAM",15.50)
            self.individual_program=self.make_program(db,self.event,"Free Individual Program","INDIVIDUAL",0)
            self.other_program=self.make_program(db,self.other_event,"Other Program","INDIVIDUAL",0)
            self.reg1=self.make_registration(db,self.event,self.team_program,self.users["Participant One"],"UNIVERSITY","MY-UNI-ID")
            self.reg1_individual=self.make_registration(db,self.event,self.individual_program,self.users["Participant One"],"OUTSIDER")
            self.reg2=self.make_registration(db,self.event,self.team_program,self.users["Participant Two"],"OUTSIDER")
            self.other_reg=self.make_registration(db,self.other_event,self.other_program,self.users["Unrelated"],"OUTSIDER")
            self.team=db.execute(
                """INSERT INTO participant_teams(program_id,event_id,creator_registration_id,captain_registration_id)
                   VALUES(?,?,?,?)""",(self.team_program,self.event,self.reg1,self.reg1)
            ).lastrowid
            db.executemany("INSERT INTO participant_team_members(team_id,program_id,event_id,registration_id) VALUES(?,?,?,?)",
                           [(self.team,self.team_program,self.event,self.reg1),(self.team,self.team_program,self.event,self.reg2)])
            db.execute("INSERT INTO payment_records(registration_id,amount_cents,status,receipt_number) VALUES(?,1550,'SUCCESS','P14-RECEIPT')",(self.reg1,))
            self.payment_id=db.execute("SELECT id FROM payment_records WHERE registration_id=?",(self.reg1,)).fetchone()[0]
            db.execute("INSERT INTO qr_passes(registration_id,event_id,program_id,token_hash,pass_number,qr_image) VALUES(?,?,?,?,?,?)",
                       (self.reg1,self.event,self.team_program,"private-token-hash","P14-PASS",b"fake-image-bytes"))
            self.pass_id=db.execute("SELECT id FROM qr_passes WHERE registration_id=?",(self.reg1,)).fetchone()[0]
            db.execute("INSERT INTO attendance_entries(event_id,program_id,registration_id,verification_method,gate_staff_user_id) VALUES(?,?,?,'FACE',?)",
                       (self.event,self.team_program,self.reg1,self.users["Gate Staff"]))
            db.execute("""INSERT INTO accommodation_allocations(event_id,registration_id,participant_user_id,accommodation_name,
                       room_details,stay_from,stay_until,notes,allocated_by_user_id)
                       VALUES(?,?,?,'Participant Hostel','Room 41','2030-05-01','2030-05-03','Bring ID',?)""",
                       (self.event,self.reg1,self.users["Participant One"],self.users["Accommodation Staff"]))
            self.meeting=db.execute(
                """INSERT INTO meetings(event_id,program_id,title,description,meeting_date,start_time,end_time,meeting_link,created_by)
                   VALUES(?,?,'Team briefing','Agenda','2030-04-01','10:00','11:00','https://meet.test/p14',?)""",
                (self.event,self.team_program,self.users["Primary"]),
            ).lastrowid
            db.execute("INSERT INTO meeting_participants(meeting_id,registration_id) VALUES(?,?)",(self.meeting,self.reg1))
            db.execute("INSERT INTO meeting_teams(meeting_id,participant_team_id) VALUES(?,?)",(self.meeting,self.team))
            db.execute("INSERT INTO program_hosts(program_id,user_id,role) VALUES(?,?,'HOST')",(self.team_program,self.users["Program Host"]))
            db.execute("INSERT INTO event_gate_staff(event_id,user_id) VALUES(?,?)",(self.event,self.users["Gate Staff"]))
            db.execute("INSERT INTO event_accommodation_team(event_id,user_id) VALUES(?,?)",(self.event,self.users["Accommodation Staff"]))
            db.execute("INSERT INTO event_teams(event_id,team_name,team_leader_id) VALUES(?,?,?)",(self.event,"Operations Team",self.users["Event Team Leader"]))
            db.execute("INSERT INTO event_team_members(team_id,user_id) SELECT id,? FROM event_teams WHERE event_id=?",
                       (self.users["Event Team Leader"],self.event))
        for name,user_id in self.users.items():
            client=webapp.app.test_client()
            with client.session_transaction() as session:
                session["user_id"]=user_id
                session["role"]="root" if name == "Root" else "user"
            self.clients[name]=client

    def tearDown(self):
        self.temp_dir.cleanup()

    @staticmethod
    def make_event(db,owner_id,name):
        request_id=db.execute("INSERT INTO event_requests(requester_id,event_title,description,proposed_date,venue) VALUES(?,?,'Info','2030-04-01','Hall')",
                              (owner_id,name)).lastrowid
        return db.execute("INSERT INTO events(event_request_id,event_name,start_date,end_date,primary_convener_id) VALUES(?,?,date('now','+5 day'),date('now','+6 day'),?)",
                          (request_id,name,owner_id)).lastrowid

    @staticmethod
    def make_program(db,event_id,name,mode,fee):
        start=datetime(2030,4,1,10)
        return db.execute("""INSERT INTO programs(event_id,program_name,category,participation_mode,team_size,start_at,end_at,
                          registration_deadline,venue,fee) VALUES(?,?,'Workshop',?,?,?,?,?,?,?)""",
                          (event_id,name,mode,3 if mode=='TEAM' else None,start.isoformat(),
                           (start+timedelta(hours=2)).isoformat(),(start-timedelta(days=1)).isoformat(),"Main Hall",fee)).lastrowid

    @staticmethod
    def make_registration(db,event_id,program_id,user_id,kind,institute_id=None):
        person=db.execute("SELECT full_name,email,phone,institution FROM users WHERE id=?",(user_id,)).fetchone()
        mode=db.execute("SELECT participation_mode FROM programs WHERE id=?",(program_id,)).fetchone()[0]
        return db.execute("""INSERT INTO participant_registrations(event_id,program_id,user_id,participant_type,institute_id,
                          full_name,email,phone,institution,registration_mode) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                          (event_id,program_id,user_id,kind,institute_id,person["full_name"],person["email"],person["phone"],
                           person["institution"],mode)).lastrowid

    def test_dashboard_requires_login(self):
        self.assertEqual(webapp.app.test_client().get("/dashboard").status_code,302)
        self.assertEqual(webapp.app.test_client().get("/profile").status_code,302)

    def test_participant_dashboard_shows_only_owned_registration_data(self):
        page=self.clients["Participant One"].get("/dashboard")
        self.assertEqual(page.status_code,200)
        for label in (b"Team Program",b"Free Individual Program",b"MY-UNI-ID",b"View receipt",b"P14-PASS",
                      b"Entered / Verified",b"FACE",b"Participant Hostel",b"Room 41",b"Team briefing",b"https://meet.test/p14"):
            self.assertIn(label,page.data)
        for private in (b"two@p14.test",b"private-token-hash",b"face-embedding-private",b"password-hash-private",b"allocated_by_user_id"):
            self.assertNotIn(private,page.data)
        for nav in (b"Profile",b"My registrations",b"Meetings",b"/logout"):
            self.assertIn(nav,page.data)
        self.assertNotIn(b"Root review",page.data)
        self.assertNotIn(b"Platform analytics",page.data)
        self.assertIn(b"Free / No payment required",page.data)
        self.assertIn(b"You are the captain",page.data)

    def test_dashboard_registrations_and_personal_details_are_scoped(self):
        page=self.clients["Participant Two"].get("/dashboard")
        self.assertEqual(page.status_code,200)
        self.assertIn(b"Team Program",page.data)
        self.assertNotIn(b"MY-UNI-ID",page.data)
        self.assertNotIn(b"P14-RECEIPT",page.data)
        self.assertNotIn(b"P14-PASS",page.data)
        self.assertNotIn(b"Participant Hostel",page.data)
        self.assertNotIn(b"Unrelated Event",page.data)

    def test_private_registration_payment_and_qr_routes_are_owner_scoped(self):
        client=self.clients["Participant Two"]
        self.assertEqual(client.get(f"/participant-registrations/{self.reg1}").status_code,404)
        self.assertEqual(client.get(f"/payments/{self.payment_id}/receipt").status_code,404)
        self.assertEqual(client.get(f"/participant-registrations/{self.reg1}/qr-pass").status_code,404)
        self.assertEqual(self.clients["Participant One"].get(f"/participant-registrations/{self.reg1}").status_code,200)

    def test_team_information_uses_existing_team_membership_authorization(self):
        self.assertEqual(self.clients["Participant One"].get(f"/participant-teams/{self.team}").status_code,200)
        self.assertEqual(self.clients["Participant Two"].get(f"/participant-teams/{self.team}").status_code,200)
        self.assertEqual(self.clients["Unrelated"].get(f"/participant-teams/{self.team}").status_code,404)
        page=self.clients["Participant One"].get("/dashboard")
        self.assertIn(b"Participant Two",page.data)
        self.assertNotIn(b"two@p14.test",page.data)

    def test_attendance_accommodation_and_meetings_show_only_for_associated_user(self):
        one=self.clients["Participant One"].get("/dashboard").data
        two=self.clients["Participant Two"].get("/dashboard").data
        self.assertIn(b"Entered / Verified",one)
        self.assertIn(b"Participant Hostel",one)
        self.assertIn(b"Team briefing",one)
        self.assertNotIn(b"Entered / Verified",two)
        self.assertNotIn(b"Participant Hostel",two)
        self.assertIn(b"Team briefing",two)  # Associated by authorized team membership.
        self.assertEqual(self.clients["Unrelated"].get(f"/meetings/{self.meeting}").status_code,403)

    def test_profile_updates_only_the_logged_in_users_allowed_fields(self):
        client=self.clients["Participant One"]
        response=client.post("/profile",data={"full_name":"Updated Participant","phone":"999","institution":"New Institute",
                                             "email":"attacker@p14.test","role":"root","affiliation":"external",
                                             "face_embedding":"forged-embedding","user_id":self.users["Participant Two"]})
        self.assertEqual(response.status_code,302)
        with database.get_db() as db:
            own=db.execute("SELECT full_name,email,phone,institution,role,affiliation,face_embedding FROM users WHERE id=?",
                           (self.users["Participant One"],)).fetchone()
            other=db.execute("SELECT full_name FROM users WHERE id=?",(self.users["Participant Two"],)).fetchone()
        self.assertEqual(tuple(own),("Updated Participant","one@p14.test","999","New Institute","user","external","face-embedding-private"))
        self.assertEqual(other["full_name"],"Participant Two")
        self.assertEqual(client.get("/profile?user_id="+str(self.users["Participant Two"])).status_code,200)

    def test_profile_exposes_only_safe_fields_and_face_status(self):
        page=self.clients["Participant One"].get("/profile")
        self.assertEqual(page.status_code,200)
        self.assertIn(b"Your face is registered",page.data)
        self.assertNotIn(b"face-embedding-private",page.data)
        self.assertNotIn(b"password-hash-private",page.data)
        self.assertNotIn(b"forged-embedding",page.data)

    def test_participants_cannot_access_analytics_or_convener_management(self):
        client=self.clients["Participant One"]
        self.assertEqual(client.get(f"/convener/events/{self.event}/analytics").status_code,403)
        self.assertEqual(client.get(f"/programs/{self.team_program}/analytics").status_code,403)
        self.assertEqual(client.get("/root/analytics").status_code,403)
        self.assertEqual(client.get(f"/convener/events/{self.event}").status_code,404)
        self.assertEqual(client.get(f"/gate/events/{self.event}").status_code,403)
        self.assertEqual(client.get(f"/accommodation/events/{self.event}").status_code,403)

    def test_existing_event_role_permissions_remain_available(self):
        self.assertEqual(self.clients["Primary"].get(f"/convener/events/{self.event}").status_code,200)
        self.assertEqual(self.clients["CoConvener"].get(f"/convener/events/{self.event}").status_code,200)
        self.assertEqual(self.clients["Gate Staff"].get(f"/gate/events/{self.event}").status_code,200)
        self.assertEqual(self.clients["Accommodation Staff"].get(f"/accommodation/events/{self.event}").status_code,200)
        self.assertEqual(self.clients["Program Host"].get(f"/programs/{self.team_program}").status_code,200)

    def test_flask_starts_and_serves_a_page(self):
        server=make_server("127.0.0.1",0,webapp.app,threaded=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            with urlopen(f"http://127.0.0.1:{server.server_port}/login",timeout=5) as response:
                self.assertEqual(response.status,200)
                self.assertIn(b"Log in",response.read())
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
