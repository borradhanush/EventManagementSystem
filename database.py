import sqlite3
from contextlib import contextmanager
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "database" / "event_management.db"


@contextmanager
def get_db():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                phone TEXT DEFAULT '',
                institution TEXT DEFAULT '',
                affiliation TEXT NOT NULL CHECK (affiliation IN ('internal', 'external')),
                role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'root')),
                face_image TEXT DEFAULT NULL,
                face_embedding TEXT DEFAULT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
                profile_completed INTEGER NOT NULL DEFAULT 1 CHECK (profile_completed IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
        if "face_embedding" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN face_embedding TEXT DEFAULT NULL")
        if "role" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        if "email_verified" not in columns:
            # Accounts created before OTP verification remain usable.
            db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1 CHECK (email_verified IN (0, 1))")
        if "profile_completed" not in columns:
            # Treat pre-existing accounts as complete; new OTP registrations explicitly start incomplete.
            db.execute("ALTER TABLE users ADD COLUMN profile_completed INTEGER NOT NULL DEFAULT 1 CHECK (profile_completed IN (0, 1))")
        db.execute("""
            CREATE TABLE IF NOT EXISTS pending_registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_pending_registrations_expires ON pending_registrations(expires_at)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS pending_registration_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pending_registration_id INTEGER NOT NULL REFERENCES pending_registrations(id) ON DELETE CASCADE,
                otp_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
                used_at TEXT DEFAULT NULL,
                invalidated_at TEXT DEFAULT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_pending_registration_otp_owner_created ON pending_registration_otps(pending_registration_id, created_at DESC)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS email_verification_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                otp_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 5),
                used_at TEXT DEFAULT NULL,
                invalidated_at TEXT DEFAULT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_email_verification_user_created ON email_verification_otps(user_id, created_at DESC)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS event_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                requester_id INTEGER NOT NULL REFERENCES users(id),
                event_title TEXT NOT NULL,
                description TEXT NOT NULL,
                proposed_date TEXT NOT NULL,
                venue TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected')),
                root_note TEXT DEFAULT '',
                reviewed_by INTEGER REFERENCES users(id),
                requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TEXT DEFAULT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS event_request_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_request_id INTEGER NOT NULL REFERENCES event_requests(id),
                actor_id INTEGER NOT NULL REFERENCES users(id),
                action TEXT NOT NULL CHECK (action IN ('submitted', 'edited', 'resubmitted', 'approved', 'rejected')),
                event_title TEXT NOT NULL,
                description TEXT NOT NULL,
                proposed_date TEXT NOT NULL,
                venue TEXT NOT NULL,
                root_note TEXT NOT NULL DEFAULT '',
                occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_requests_requester ON event_requests(requester_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_requests_status ON event_requests(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_request_history_request ON event_request_history(event_request_id, id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_request_id INTEGER NOT NULL UNIQUE REFERENCES event_requests(id),
                event_name TEXT NOT NULL,
                organization_university TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL DEFAULT 'General',
                description TEXT NOT NULL DEFAULT '',
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                venue TEXT NOT NULL DEFAULT '',
                visibility TEXT NOT NULL DEFAULT 'PUBLIC'
                    CHECK (visibility IN ('PUBLIC', 'PRIVATE')),
                status TEXT NOT NULL DEFAULT 'UPCOMING'
                    CHECK (status IN ('UPCOMING', 'ONGOING', 'COMPLETED')),
                primary_convener_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_primary_convener ON events(primary_convener_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_visibility ON events(visibility)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS event_co_conveners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (event_id, user_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_co_conveners_user ON event_co_conveners(user_id, event_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS event_gate_staff (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (event_id, user_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_gate_staff_user ON event_gate_staff(user_id, event_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS event_accommodation_team (
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (event_id, user_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_accommodation_team_user ON event_accommodation_team(user_id, event_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS event_teams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                team_name TEXT NOT NULL COLLATE NOCASE,
                description TEXT NOT NULL DEFAULT '',
                team_leader_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (event_id, team_name),
                UNIQUE (event_id, team_leader_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_teams_event ON event_teams(event_id, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_teams_leader ON event_teams(team_leader_id, event_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS event_team_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                team_id INTEGER NOT NULL REFERENCES event_teams(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (team_id, user_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_event_team_members_user ON event_team_members(user_id, team_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS programs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                program_name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                category TEXT NOT NULL,
                participation_mode TEXT NOT NULL CHECK (participation_mode IN ('INDIVIDUAL','TEAM')),
                team_size INTEGER DEFAULT NULL,
                start_at TEXT NOT NULL,
                end_at TEXT NOT NULL,
                registration_deadline TEXT NOT NULL,
                venue TEXT NOT NULL,
                fee REAL NOT NULL DEFAULT 0 CHECK (fee >= 0),
                status TEXT NOT NULL DEFAULT 'UPCOMING'
                    CHECK (status IN ('UPCOMING','ONGOING','COMPLETED','CANCELLED')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (
                    (participation_mode='INDIVIDUAL' AND team_size IS NULL) OR
                    (participation_mode='TEAM' AND typeof(team_size)='integer' AND team_size BETWEEN 2 AND 100)
                ),
                CHECK (registration_deadline <= start_at),
                CHECK (end_at > start_at)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_programs_event ON programs(event_id, start_at, id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_programs_status ON programs(status, start_at, end_at)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_program_id_event_unique ON programs(id, event_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS program_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK (role IN ('HOST','CO_HOST')),
                assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (program_id, user_id),
                UNIQUE (program_id, role)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_program_hosts_user ON program_hosts(user_id, program_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS participant_registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                program_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                participant_type TEXT NOT NULL CHECK (participant_type IN ('UNIVERSITY','OUTSIDER')),
                institute_id TEXT DEFAULT NULL,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT NOT NULL DEFAULT '',
                institution TEXT NOT NULL DEFAULT '',
                registration_mode TEXT NOT NULL CHECK (registration_mode IN ('INDIVIDUAL','TEAM')),
                accommodation_required INTEGER NOT NULL DEFAULT 1 CHECK (accommodation_required IN (0, 1)),
                registered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (program_id, user_id),
                CHECK (
                    (participant_type='UNIVERSITY' AND institute_id IS NOT NULL AND length(trim(institute_id))>0) OR
                    (participant_type='OUTSIDER' AND institute_id IS NULL)
                ),
                FOREIGN KEY (program_id, event_id) REFERENCES programs(id, event_id) ON DELETE CASCADE
            )
        """)
        registration_columns = {row["name"] for row in db.execute("PRAGMA table_info(participant_registrations)")}
        if "accommodation_required" not in registration_columns:
            # Existing participants keep the prior ability to receive allocations.
            db.execute("ALTER TABLE participant_registrations ADD COLUMN accommodation_required INTEGER NOT NULL DEFAULT 1 CHECK (accommodation_required IN (0, 1))")
        db.execute("CREATE INDEX IF NOT EXISTS idx_participant_reg_event_program ON participant_registrations(event_id, program_id, registered_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_participant_reg_user ON participant_registrations(user_id, registered_at)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_participant_registration_scope ON participant_registrations(id, program_id, event_id)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_participant_registration_accommodation_scope ON participant_registrations(id, event_id, user_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS accommodation_allocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                registration_id INTEGER NOT NULL,
                participant_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                accommodation_name TEXT NOT NULL,
                room_details TEXT NOT NULL,
                stay_from TEXT NOT NULL,
                stay_until TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                allocated_by_user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (event_id, participant_user_id),
                CHECK (stay_until >= stay_from),
                FOREIGN KEY (registration_id, event_id, participant_user_id)
                    REFERENCES participant_registrations(id, event_id, user_id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_accommodation_event ON accommodation_allocations(event_id, stay_from, stay_until)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_accommodation_participant ON accommodation_allocations(participant_user_id, event_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS participant_teams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                program_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                creator_registration_id INTEGER NOT NULL,
                captain_registration_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISBANDED')),
                disbanded_at TEXT DEFAULT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (id, program_id, event_id),
                UNIQUE (program_id, captain_registration_id),
                FOREIGN KEY (program_id, event_id) REFERENCES programs(id, event_id) ON DELETE CASCADE,
                FOREIGN KEY (creator_registration_id, program_id, event_id)
                    REFERENCES participant_registrations(id, program_id, event_id) ON DELETE CASCADE,
                FOREIGN KEY (captain_registration_id, program_id, event_id)
                    REFERENCES participant_registrations(id, program_id, event_id) ON DELETE CASCADE
            )
        """)
        team_columns = {row["name"] for row in db.execute("PRAGMA table_info(participant_teams)")}
        if "creator_registration_id" not in team_columns:
            db.execute("ALTER TABLE participant_teams ADD COLUMN creator_registration_id INTEGER REFERENCES participant_registrations(id)")
            db.execute("UPDATE participant_teams SET creator_registration_id=captain_registration_id WHERE creator_registration_id IS NULL")
        if "status" not in team_columns:
            db.execute("ALTER TABLE participant_teams ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISBANDED'))")
        if "disbanded_at" not in team_columns:
            db.execute("ALTER TABLE participant_teams ADD COLUMN disbanded_at TEXT DEFAULT NULL")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_participant_team_creator ON participant_teams(program_id, creator_registration_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_participant_teams_program ON participant_teams(program_id, event_id, created_at)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS participant_team_members (
                team_id INTEGER NOT NULL,
                program_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                registration_id INTEGER NOT NULL,
                joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (team_id, registration_id),
                UNIQUE (program_id, registration_id),
                FOREIGN KEY (team_id, program_id, event_id)
                    REFERENCES participant_teams(id, program_id, event_id) ON DELETE CASCADE,
                FOREIGN KEY (registration_id, program_id, event_id)
                    REFERENCES participant_registrations(id, program_id, event_id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_participant_team_members_registration ON participant_team_members(registration_id, program_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS payment_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                registration_id INTEGER NOT NULL REFERENCES participant_registrations(id) ON DELETE CASCADE,
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                status TEXT NOT NULL CHECK (status IN ('PENDING','SUCCESS','FAILED')),
                receipt_number TEXT DEFAULT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                processed_at TEXT DEFAULT NULL,
                CHECK (
                    (status='SUCCESS' AND receipt_number IS NOT NULL) OR
                    (status IN ('PENDING','FAILED') AND receipt_number IS NULL)
                )
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_payment_records_registration ON payment_records(registration_id, id)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_success_per_registration ON payment_records(registration_id) WHERE status='SUCCESS'")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_receipt_unique ON payment_records(receipt_number) WHERE receipt_number IS NOT NULL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS qr_passes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                registration_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                program_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                pass_number TEXT NOT NULL UNIQUE,
                qr_image BLOB NOT NULL,
                status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                revoked_at TEXT DEFAULT NULL,
                FOREIGN KEY (registration_id, program_id, event_id)
                    REFERENCES participant_registrations(id, program_id, event_id) ON DELETE CASCADE,
                FOREIGN KEY (program_id, event_id)
                    REFERENCES programs(id, event_id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_qr_pass_active_registration ON qr_passes(registration_id) WHERE status='ACTIVE'")
        db.execute("CREATE INDEX IF NOT EXISTS idx_qr_pass_event_program ON qr_passes(event_id, program_id, status)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS attendance_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                program_id INTEGER NOT NULL,
                registration_id INTEGER NOT NULL,
                verification_method TEXT NOT NULL CHECK (verification_method IN ('FACE','QR')),
                gate_staff_user_id INTEGER NOT NULL REFERENCES users(id),
                entered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (registration_id, program_id),
                FOREIGN KEY (registration_id, program_id, event_id)
                    REFERENCES participant_registrations(id, program_id, event_id) ON DELETE CASCADE,
                FOREIGN KEY (program_id, event_id)
                    REFERENCES programs(id, event_id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_attendance_event_program ON attendance_entries(event_id, program_id, entered_at)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_attendance_gate_staff ON attendance_entries(gate_staff_user_id, entered_at)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS meetings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
                program_id INTEGER DEFAULT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                meeting_date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                meeting_link TEXT NOT NULL,
                created_by INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (end_time > start_time),
                UNIQUE (id, event_id),
                FOREIGN KEY (program_id, event_id) REFERENCES programs(id, event_id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_meetings_event_date ON meetings(event_id, meeting_date, start_time)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_meetings_program ON meetings(program_id, event_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS meeting_participants (
                meeting_id INTEGER NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
                registration_id INTEGER NOT NULL REFERENCES participant_registrations(id) ON DELETE CASCADE,
                PRIMARY KEY (meeting_id, registration_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_meeting_participants_registration ON meeting_participants(registration_id, meeting_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS meeting_teams (
                meeting_id INTEGER NOT NULL REFERENCES meetings(id) ON DELETE CASCADE,
                participant_team_id INTEGER NOT NULL REFERENCES participant_teams(id) ON DELETE CASCADE,
                PRIMARY KEY (meeting_id, participant_team_id)
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_meeting_teams_team ON meeting_teams(participant_team_id, meeting_id)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_event_teams_id_event ON event_teams(id, event_id)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS meeting_internal_group_recipients (
                meeting_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                group_type TEXT NOT NULL CHECK (group_type IN
                    ('CONVENERS','GATE_STAFF','ACCOMMODATION_TEAM','PROGRAM_HOSTS')),
                PRIMARY KEY (meeting_id, group_type),
                FOREIGN KEY (meeting_id, event_id) REFERENCES meetings(id, event_id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_meeting_internal_groups_event ON meeting_internal_group_recipients(event_id, group_type)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS meeting_event_teams (
                meeting_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                event_team_id INTEGER NOT NULL,
                PRIMARY KEY (meeting_id, event_team_id),
                FOREIGN KEY (meeting_id, event_id) REFERENCES meetings(id, event_id) ON DELETE CASCADE,
                FOREIGN KEY (event_team_id, event_id) REFERENCES event_teams(id, event_id) ON DELETE CASCADE
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_meeting_event_teams_event ON meeting_event_teams(event_id, event_team_id)")


if __name__ == "__main__":
    init_db()
    print(f"Database initialized: {DATABASE_PATH}")
