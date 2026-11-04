import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import app as webapp
import database


class AnalyticsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        database.DATABASE_PATH = Path(self.temp_dir.name) / "analytics_test.db"
        database.init_db()
        webapp.app.config.update(TESTING=True, SECRET_KEY="analytics-tests")
        self.users = {}
        self.clients = {}
        with database.get_db() as db:
            for name, role in [
                ("Primary Person", "user"), ("Co Person", "user"), ("Other Owner", "user"),
                ("University Participant", "user"), ("Outside Participant", "user"),
                ("Third Participant", "user"), ("Event Team Leader", "user"),
                ("Gate Worker", "user"), ("Accommodation Worker", "user"),
                ("Program Host", "user"), ("Root Account", "root"),
            ]:
                email = name.lower().replace(" ", ".") + "@analytics.test"
                cursor = db.execute(
                    """INSERT INTO users(full_name,email,password_hash,affiliation,role,face_embedding)
                       VALUES (?,?,?,'internal',?,'private-face-embedding')""",
                    (name,email,"password-hash-secret",role),
                )
                self.users[name] = cursor.lastrowid
            self.event = self.make_event(db, self.users["Primary Person"], "Analytics Event")
            db.execute("INSERT INTO event_co_conveners(event_id,user_id) VALUES (?,?)",
                       (self.event,self.users["Co Person"]))
            self.other_event = self.make_event(db, self.users["Other Owner"], "Other Event Private")
            self.program_team = self.make_program(db, self.event, "Team Program", "TEAM", 4, 25.0)
            self.program_individual = self.make_program(db, self.event, "Individual Program", "INDIVIDUAL", None, 0)
            self.program_cancelled = self.make_program(db, self.event, "Cancelled Program", "INDIVIDUAL", None, 0, cancelled=True)
            self.other_program = self.make_program(db, self.other_event, "Other Event Program", "INDIVIDUAL", None, 0)
            self.reg1 = self.make_registration(db, self.event, self.program_team, "University Participant", "UNIVERSITY", "UNI-1")
            self.reg2 = self.make_registration(db, self.event, self.program_team, "Outside Participant", "OUTSIDER")
            self.reg3 = self.make_registration(db, self.event, self.program_individual, "Third Participant", "UNIVERSITY", "UNI-3")
            self.other_reg = self.make_registration(db, self.other_event, self.other_program, "Other Owner", "OUTSIDER")
            db.execute("INSERT INTO event_teams(event_id,team_name,team_leader_id) VALUES (?,?,?)",
                       (self.event,"Event Staff Team",self.users["Event Team Leader"]))
            db.execute("INSERT INTO event_team_members(team_id,user_id) SELECT id,? FROM event_teams WHERE event_id=?",
                       (self.users["Event Team Leader"],self.event))
            db.execute("INSERT INTO event_gate_staff(event_id,user_id) VALUES (?,?)",
                       (self.event,self.users["Gate Worker"]))
            db.execute("INSERT INTO event_accommodation_team(event_id,user_id) VALUES (?,?)",
                       (self.event,self.users["Accommodation Worker"]))
            db.execute("INSERT INTO program_hosts(program_id,user_id,role) VALUES (?,?,'HOST')",
                       (self.program_team,self.users["Program Host"]))
            db.execute("INSERT INTO participant_teams(program_id,event_id,creator_registration_id,captain_registration_id) VALUES (?,?,?,?)",
                       (self.program_team,self.event,self.reg1,self.reg1))
            db.executemany("INSERT INTO participant_team_members(team_id,program_id,event_id,registration_id) VALUES (?,?,?,?)",
                           [(1,self.program_team,self.event,self.reg1),(1,self.program_team,self.event,self.reg2)])
            db.execute("INSERT INTO payment_records(registration_id,amount_cents,status,receipt_number) VALUES (?,1000,'SUCCESS','ANALYTICS-R1')", (self.reg1,))
            db.execute("INSERT INTO payment_records(registration_id,amount_cents,status) VALUES (?,2500,'FAILED')", (self.reg2,))
            db.execute("INSERT INTO payment_records(registration_id,amount_cents,status) VALUES (?,2500,'PENDING')", (self.reg3,))
            db.execute("INSERT INTO qr_passes(registration_id,event_id,program_id,token_hash,pass_number,qr_image) VALUES (?,?,?,?,?,?)",
                       (self.reg1,self.event,self.program_team,"sensitive-qr-token-hash","PASS-PRIVATE",b"private-qr"))
            db.execute("INSERT INTO attendance_entries(event_id,program_id,registration_id,verification_method,gate_staff_user_id) VALUES (?,?,?,'FACE',?)",
                       (self.event,self.program_team,self.reg1,self.users["Gate Worker"]))
            db.execute("INSERT INTO attendance_entries(event_id,program_id,registration_id,verification_method,gate_staff_user_id) VALUES (?,?,?,'QR',?)",
                       (self.event,self.program_team,self.reg2,self.users["Gate Worker"]))
            db.execute("""INSERT INTO accommodation_allocations(event_id,registration_id,participant_user_id,accommodation_name,
                       room_details,stay_from,stay_until,notes,allocated_by_user_id)
                       VALUES (?,?,?,'PRIVATE DORM DETAIL','ROOM-SECRET','2026-10-20','2026-10-21','PRIVATE NOTE',?)""",
                       (self.event,self.reg2,self.users["Outside Participant"],self.users["Accommodation Worker"]))
            now = datetime.now()
            meeting_day = (now + timedelta(days=2)).date().isoformat()
            for program_id in (None,self.program_team):
                db.execute("""INSERT INTO meetings(event_id,program_id,title,description,meeting_date,start_time,end_time,meeting_link,created_by)
                           VALUES (?,?,?,'Agenda',?,'10:00','11:00','https://meet.test/hidden',?)""",
                           (self.event,program_id,"Private Meeting Title",meeting_day,self.users["Primary Person"]))
        for name,user_id in self.users.items():
            client=webapp.app.test_client()
            with client.session_transaction() as session:
                session["user_id"]=user_id
                session["role"]="root" if name == "Root Account" else "user"
            self.clients[name]=client

    def tearDown(self):
        self.temp_dir.cleanup()

    @staticmethod
    def make_event(db, owner_id, name):
        request_id=db.execute("""INSERT INTO event_requests(requester_id,event_title,description,proposed_date,venue)
                             VALUES (?,?,'Description','2026-10-20','Hall')""",(owner_id,name)).lastrowid
        return db.execute("""INSERT INTO events(event_request_id,event_name,start_date,end_date,primary_convener_id)
                          VALUES (?,?,date('now'),date('now'),?)""",(request_id,name,owner_id)).lastrowid

    @staticmethod
    def make_program(db,event_id,name,mode,team_size,fee,cancelled=False):
        start=datetime(2030,1,1,10,0)
        deadline=start-timedelta(hours=2)
        status="CANCELLED" if cancelled else "UPCOMING"
        return db.execute("""INSERT INTO programs(event_id,program_name,category,participation_mode,team_size,start_at,end_at,
                          registration_deadline,venue,fee,status) VALUES (?,?,'Contest',?,?,?,?,?,?,?,?)""",
                          (event_id,name,mode,team_size,start.isoformat(),(start+timedelta(hours=2)).isoformat(),
                           deadline.isoformat(),"Hall",fee,status)).lastrowid

    def make_registration(self,db,event_id,program_id,name,kind,institute_id=None):
        user_id=self.users[name]
        user=db.execute("SELECT full_name,email FROM users WHERE id=?",(user_id,)).fetchone()
        return db.execute("""INSERT INTO participant_registrations(event_id,program_id,user_id,participant_type,institute_id,
                          full_name,email,registration_mode) VALUES (?,?,?,?,?,?,?,?)""",
                          (event_id,program_id,user_id,kind,institute_id,user["full_name"],user["email"],
                           "TEAM" if program_id == getattr(self,"program_team",None) else "INDIVIDUAL")).lastrowid

    def test_only_primary_and_co_convener_can_open_event_analytics(self):
        for name in ("Primary Person","Co Person"):
            self.assertEqual(self.clients[name].get(f"/convener/events/{self.event}/analytics").status_code,200)
        for name in ("Other Owner","University Participant","Event Team Leader","Gate Worker",
                     "Accommodation Worker","Program Host"):
            self.assertEqual(self.clients[name].get(f"/convener/events/{self.event}/analytics").status_code,403,name)

    def test_event_registration_program_payment_attendance_accommodation_meeting_counts(self):
        response=self.clients["Primary Person"].get(f"/convener/events/{self.event}/analytics")
        page=response.data
        self.assertIn(b"Team Program",page)
        self.assertIn(b"3",page)
        self.assertIn(b"2",page)
        self.assertIn(b"Cancelled Program",page)
        self.assertIn(b"10.00",page)
        self.assertNotIn(b"PRIVATE DORM DETAIL",page)
        self.assertNotIn(b"PRIVATE NOTE",page)
        with database.get_db() as db:
            event= db.execute("SELECT * FROM events WHERE id=?",(self.event,)).fetchone()
            data=webapp.event_analytics_data(db,event)
        self.assertEqual(tuple(data["registrations"]),(3,2,1))
        self.assertEqual(data["payments"]["paid_registrations"],2)
        self.assertEqual(data["payments"]["successful_count"],1)
        self.assertEqual(data["payments"]["failed_count"],1)
        self.assertEqual(data["payments"]["pending_count"],1)
        self.assertEqual(data["payments"]["successful_amount_cents"],1000)
        self.assertEqual(tuple(data["attendance"]),(2,1,1))
        self.assertEqual(tuple(data["accommodation"]),(3,1))
        self.assertEqual(tuple(data["meetings"]),(2,1,1))
        self.assertEqual(len(data["programs"]),3)
        self.assertEqual([p["registration_count"] for p in data["programs"]],[2,1,0])
        self.assertEqual(data["programs"][0]["team_count"],1)
        self.assertEqual(data["program_status_counts"],{"UPCOMING":2,"ONGOING":0,"COMPLETED":0,"CANCELLED":1})

    def test_program_analytics_counts_and_event_isolation(self):
        response=self.clients["Co Person"].get(f"/programs/{self.program_team}/analytics")
        self.assertEqual(response.status_code,200)
        self.assertIn(b"10.00",response.data)
        self.assertNotIn(b"analytics.test",response.data)
        self.assertNotIn(b"PRIVATE DORM DETAIL",response.data)
        with database.get_db() as db:
            program=db.execute("SELECT * FROM programs WHERE id=?",(self.program_team,)).fetchone()
            data=webapp.program_analytics_data(db,program)
        self.assertEqual(tuple(data["registrations"]),(2,1,1))
        self.assertEqual(data["team_count"],1)
        self.assertEqual(data["payments"]["successful_count"],1)
        self.assertEqual(data["payments"]["amount_cents"],1000)
        self.assertEqual(tuple(data["attendance"]),(2,1,1))
        self.assertEqual(data["accommodation_count"],1)
        self.assertEqual(data["meeting_count"],1)
        self.assertEqual(self.clients["Other Owner"].get(f"/programs/{self.program_team}/analytics").status_code,403)
        self.assertEqual(self.clients["Program Host"].get(f"/programs/{self.program_team}/analytics").status_code,403)

    def test_root_sees_aggregate_only_and_cannot_open_scoped_analytics(self):
        root=self.clients["Root Account"]
        response=root.get("/root/analytics")
        self.assertEqual(response.status_code,200)
        for label in (b"Total events",b"Upcoming events",b"Ongoing events",b"Completed events",
                      b"Total programs",b"Total registrations",b"Successful mock payments"):
            self.assertIn(label,response.data)
        for secret in (b"analytics.test",b"password-hash-secret",b"private-face-embedding",
                       b"sensitive-qr-token-hash",b"PASS-PRIVATE",b"PRIVATE DORM DETAIL",b"ROOM-SECRET"):
            self.assertNotIn(secret,response.data)
        self.assertIn(b"Other Event Private",response.data)
        self.assertEqual(root.get(f"/convener/events/{self.event}/analytics").status_code,403)
        self.assertEqual(root.get(f"/programs/{self.program_team}/analytics").status_code,403)

    def test_cross_event_records_do_not_change_event_counts(self):
        with database.get_db() as db:
            event=db.execute("SELECT * FROM events WHERE id=?",(self.event,)).fetchone()
            data=webapp.event_analytics_data(db,event)
        self.assertEqual(data["registrations"]["total"],3)
        self.assertNotIn("Other Event Program",[program["program_name"] for program in data["programs"]])
        response=self.clients["Primary Person"].get(f"/convener/events/{self.event}/analytics")
        self.assertNotIn(b"Other Event Private",response.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
