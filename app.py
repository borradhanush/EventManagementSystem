import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import sys
import cv2
import numpy as np
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps
from getpass import getpass
from io import BytesIO
from pathlib import Path

import qrcode
from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_db, init_db
from email_service import EmailConfigurationError, EmailDeliveryError, send_email
from face_recognition import (
    SIMILARITY_THRESHOLD,
    FaceError,
    compare_embeddings,
    generate_embedding,
)

BASE_DIR = Path(__file__).resolve().parent


def load_application_environment(env_path=None):
    """Load local configuration without overriding OS-provided environment values."""
    load_dotenv(dotenv_path=env_path or BASE_DIR / ".env", override=False)


load_application_environment()
ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png"}
EMAIL_VERIFICATION_SESSION_KEY = "pending_email_verification_user_id"
PENDING_REGISTRATION_SESSION_KEY = "pending_registration_id"
OTP_LIFETIME_MINUTES = 10
PENDING_REGISTRATION_LIFETIME_HOURS = 24
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_SENDS_PER_HOUR = 5

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("FLASK_SECRET_KEY"),
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_COOKIE_SECURE", "0").strip().lower() in {"1", "true", "yes"},
)


def validate_runtime_configuration():
    missing = [name for name in ("SENDER_EMAIL", "APP_PASSWORD", "FLASK_SECRET_KEY") if not os.environ.get(name, "").strip()]
    if missing:
        raise SystemExit("Missing required .env configuration: " + ", ".join(missing))


@app.after_request
def prevent_sensitive_page_caching(response):
    """Keep authenticated HTML and redirects from being restored after logout."""
    if request.endpoint != "static":
        response.headers["Cache-Control"] = "private, no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user_id = session.get("user_id")
        if not isinstance(user_id, int) or current_user() is None:
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def root_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None or user["role"] != "root":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def utc_now_text():
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")


def otp_digest(user_id, code, scope="email-otp"):
    message = f"{scope}:{user_id}:{code}".encode("utf-8")
    return hmac.new(str(app.config["SECRET_KEY"]).encode("utf-8"), message, hashlib.sha256).hexdigest()


def masked_email(email):
    local, separator, domain = email.partition("@")
    if not separator:
        return "your registered email"
    return f"{local[:1]}{'*' * max(2, min(len(local) - 1, 7))}@{domain}"


def send_verification_otp(user_id, full_name, email, *, is_resend=False):
    """Persist a short-lived OTP hash and send the code through Phase 15 email service."""
    now = utc_now_text()
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT email_verified FROM users WHERE id=?", (user_id,)).fetchone()
        if user is None or user["email_verified"]:
            return False, "This account does not need email verification."
        recent = db.execute(
            "SELECT COUNT(*) AS n FROM email_verification_otps WHERE user_id=? AND created_at >= datetime('now','-1 hour')",
            (user_id,),
        ).fetchone()["n"]
        latest = db.execute(
            "SELECT created_at FROM email_verification_otps WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        if is_resend and latest:
            seconds = db.execute(
                "SELECT CAST(strftime('%s','now') - strftime('%s', ?) AS INTEGER)", (latest["created_at"],)
            ).fetchone()[0]
            if seconds < OTP_RESEND_COOLDOWN_SECONDS:
                return False, "Please wait 60 seconds between verification emails."
        if recent >= OTP_MAX_SENDS_PER_HOUR:
            return False, "Too many verification emails were requested. Try again in an hour."

        db.execute(
            "UPDATE email_verification_otps SET invalidated_at=? WHERE user_id=? AND used_at IS NULL AND invalidated_at IS NULL",
            (now, user_id),
        )
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires = (datetime.now(timezone.utc) + timedelta(minutes=OTP_LIFETIME_MINUTES)).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
        db.execute(
            "INSERT INTO email_verification_otps(user_id,otp_hash,created_at,expires_at) VALUES(?,?,?,?)",
            (user_id, otp_digest(user_id, code), now, expires),
        )
    body = (
        f"Hello {full_name},\n\n"
        f"Your Event Management Platform verification code is: {code}\n\n"
        f"This code expires in {OTP_LIFETIME_MINUTES} minutes. Do not share it with anyone.\n\n"
        "If you did not create this account, you can ignore this email.\n"
        "Event Management Platform"
    )
    try:
        send_email("Verify your Event Management Platform account", body, [email])
    except (EmailConfigurationError, EmailDeliveryError, ValueError):
        with get_db() as db:
            db.execute(
                "UPDATE email_verification_otps SET invalidated_at=? WHERE user_id=? AND otp_hash=? AND used_at IS NULL",
                (utc_now_text(), user_id, otp_digest(user_id, code)),
            )
        raise
    return True, None


def send_registration_otp(pending_id, full_name, email, *, is_resend=False):
    """Send a registration challenge without creating a users row."""
    now = utc_now_text()
    with get_db() as db:
        db.execute("BEGIN IMMEDIATE")
        pending = db.execute("SELECT id FROM pending_registrations WHERE id=? AND expires_at>?", (pending_id, now)).fetchone()
        if pending is None:
            return False, "This registration has expired. Please register again."
        recent = db.execute(
            "SELECT COUNT(*) FROM pending_registration_otps WHERE pending_registration_id=? AND created_at>=datetime('now','-1 hour')",
            (pending_id,),
        ).fetchone()[0]
        latest = db.execute(
            "SELECT created_at FROM pending_registration_otps WHERE pending_registration_id=? ORDER BY id DESC LIMIT 1",
            (pending_id,),
        ).fetchone()
        if is_resend and latest:
            seconds = db.execute("SELECT CAST(strftime('%s','now')-strftime('%s',?) AS INTEGER)", (latest["created_at"],)).fetchone()[0]
            if seconds < OTP_RESEND_COOLDOWN_SECONDS:
                return False, "Please wait 60 seconds between verification emails."
        if recent >= OTP_MAX_SENDS_PER_HOUR:
            return False, "Too many verification emails were requested. Try again in an hour."
        db.execute("UPDATE pending_registration_otps SET invalidated_at=? WHERE pending_registration_id=? AND used_at IS NULL AND invalidated_at IS NULL", (now, pending_id))
        code = f"{secrets.randbelow(1_000_000):06d}"
        expires = (datetime.now(timezone.utc) + timedelta(minutes=OTP_LIFETIME_MINUTES)).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
        db.execute("INSERT INTO pending_registration_otps(pending_registration_id,otp_hash,created_at,expires_at) VALUES(?,?,?,?)",
                   (pending_id, otp_digest(pending_id, code, "registration-otp"), now, expires))
    body = (f"Hello {full_name},\n\nYour verification code for creating an Event Management Platform account is: {code}\n\n"
            f"This six-digit code expires in {OTP_LIFETIME_MINUTES} minutes. Do not share it with anyone.\n\n"
            "If you did not request an account, you can ignore this email.\nEvent Management Platform")
    try:
        send_email("Verify your email", body, [email])
    except (EmailConfigurationError, EmailDeliveryError, ValueError):
        with get_db() as db:
            db.execute("UPDATE pending_registration_otps SET invalidated_at=? WHERE pending_registration_id=? AND otp_hash=? AND used_at IS NULL",
                       (utc_now_text(), pending_id, otp_digest(pending_id, code, "registration-otp")))
        raise
    return True, None


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not full_name or not email or not password:
            flash("Name, email, and password are required.", "error")
        elif len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
        elif len(full_name) > 120:
            flash("Full name must be 120 characters or fewer.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        else:
            try:
                with get_db() as db:
                    db.execute("DELETE FROM pending_registrations WHERE expires_at<=?", (utc_now_text(),))
                    if db.execute("SELECT 1 FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone():
                        raise sqlite3.IntegrityError("email already registered")
                    pending = db.execute("SELECT * FROM pending_registrations WHERE email=? COLLATE NOCASE", (email,)).fetchone()
                    if pending is None:
                        expires = (datetime.now(timezone.utc) + timedelta(hours=PENDING_REGISTRATION_LIFETIME_HOURS)).replace(tzinfo=None).isoformat(sep=" ", timespec="seconds")
                        cursor = db.execute("INSERT INTO pending_registrations(full_name,email,password_hash,expires_at) VALUES(?,?,?,?)",
                                            (full_name, email, generate_password_hash(password), expires))
                        pending_id = cursor.lastrowid
                    else:
                        pending_id = pending["id"]
                session.clear()
                session[PENDING_REGISTRATION_SESSION_KEY] = pending_id
                try:
                    sent, message = send_registration_otp(pending_id, full_name, email)
                    flash("Enter the verification code sent to your email." if sent else message, "success" if sent else "error")
                except (EmailConfigurationError, EmailDeliveryError, ValueError):
                    flash("We could not send the verification email. Your account has not been created. Please try again shortly.", "error")
                return redirect(url_for("verify_email"))
            except sqlite3.IntegrityError:
                flash("An account with that email already exists. Log in or use another email address.", "error")
    return render_template("register.html")


@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    registration_id = session.get(PENDING_REGISTRATION_SESSION_KEY)
    if isinstance(registration_id, int):
        with get_db() as db:
            pending = db.execute("SELECT * FROM pending_registrations WHERE id=? AND expires_at>?", (registration_id, utc_now_text())).fetchone()
        if pending is None:
            session.pop(PENDING_REGISTRATION_SESSION_KEY, None)
            flash("This registration has expired. Please register again.", "error")
            return redirect(url_for("register"))
        if request.method == "POST":
            code = request.form.get("otp", "").strip()
            if not re.fullmatch(r"[0-9]{6}", code):
                flash("Enter the six-digit verification code.", "error")
            else:
                now = utc_now_text()
                with get_db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    pending = db.execute("SELECT * FROM pending_registrations WHERE id=? AND expires_at>?", (registration_id, now)).fetchone()
                    challenge = db.execute("SELECT * FROM pending_registration_otps WHERE pending_registration_id=? AND used_at IS NULL AND invalidated_at IS NULL ORDER BY id DESC LIMIT 1", (registration_id,)).fetchone()
                    if pending is None:
                        session.pop(PENDING_REGISTRATION_SESSION_KEY, None)
                        flash("This registration has expired. Please register again.", "error")
                    elif challenge is None:
                        flash("That code is no longer active. Request a new code.", "error")
                    elif challenge["expires_at"] <= now:
                        db.execute("UPDATE pending_registration_otps SET invalidated_at=? WHERE id=?", (now, challenge["id"]))
                        flash("That code has expired. Request a new code.", "error")
                    elif challenge["attempt_count"] >= OTP_MAX_ATTEMPTS:
                        db.execute("UPDATE pending_registration_otps SET invalidated_at=? WHERE id=?", (now, challenge["id"]))
                        flash("Too many incorrect attempts. Request a new code.", "error")
                    elif hmac.compare_digest(challenge["otp_hash"], otp_digest(registration_id, code, "registration-otp")):
                        db.execute("UPDATE pending_registration_otps SET used_at=? WHERE id=?", (now, challenge["id"]))
                        try:
                            db.execute("""INSERT INTO users(full_name,email,password_hash,phone,institution,affiliation,email_verified,profile_completed)
                                          VALUES(?,?,?,'','', 'internal',1,0)""",
                                       (pending["full_name"], pending["email"], pending["password_hash"]))
                            db.execute("DELETE FROM pending_registrations WHERE id=?", (registration_id,))
                            session.pop(PENDING_REGISTRATION_SESSION_KEY, None)
                            flash("Email verified and account created. You can now log in and complete your profile.", "success")
                            return redirect(url_for("login"))
                        except sqlite3.IntegrityError:
                            db.execute("DELETE FROM pending_registrations WHERE id=?", (registration_id,))
                            session.pop(PENDING_REGISTRATION_SESSION_KEY, None)
                            flash("An account with that email already exists. Please log in.", "error")
                            return redirect(url_for("login"))
                    else:
                        next_count = challenge["attempt_count"] + 1
                        db.execute("UPDATE pending_registration_otps SET attempt_count=?,invalidated_at=CASE WHEN ? >= ? THEN ? ELSE invalidated_at END WHERE id=?",
                                   (next_count, next_count, OTP_MAX_ATTEMPTS, now, challenge["id"]))
                        flash("That verification code is incorrect.", "error")
        return render_template("verify_email.html", email=masked_email(pending["email"]))

    pending_id = session.get(EMAIL_VERIFICATION_SESSION_KEY)
    if not isinstance(pending_id, int):
        flash("Start by registering or logging in with your account to verify your email.", "error")
        return redirect(url_for("register"))
    with get_db() as db:
        user = db.execute("SELECT id,full_name,email,email_verified FROM users WHERE id=?", (pending_id,)).fetchone()
    if user is None:
        session.pop(EMAIL_VERIFICATION_SESSION_KEY, None)
        flash("We could not find that pending account. Please register again.", "error")
        return redirect(url_for("register"))
    if user["email_verified"]:
        session.pop(EMAIL_VERIFICATION_SESSION_KEY, None)
        flash("Your email is already verified. You can log in.", "success")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        if not re.fullmatch(r"[0-9]{6}", code):
            flash("Enter the six-digit verification code.", "error")
        else:
            now = utc_now_text()
            with get_db() as db:
                db.execute("BEGIN IMMEDIATE")
                challenge = db.execute(
                    "SELECT * FROM email_verification_otps WHERE user_id=? AND used_at IS NULL AND invalidated_at IS NULL ORDER BY id DESC LIMIT 1",
                    (pending_id,),
                ).fetchone()
                if challenge is None:
                    flash("That code is no longer active. Request a new code.", "error")
                elif challenge["expires_at"] <= now:
                    db.execute("UPDATE email_verification_otps SET invalidated_at=? WHERE id=?", (now, challenge["id"]))
                    flash("That code has expired. Request a new code.", "error")
                elif challenge["attempt_count"] >= OTP_MAX_ATTEMPTS:
                    db.execute("UPDATE email_verification_otps SET invalidated_at=? WHERE id=?", (now, challenge["id"]))
                    flash("Too many incorrect attempts. Request a new code.", "error")
                elif hmac.compare_digest(challenge["otp_hash"], otp_digest(pending_id, code)):
                    updated = db.execute(
                        "UPDATE email_verification_otps SET used_at=? WHERE id=? AND used_at IS NULL AND invalidated_at IS NULL AND attempt_count < ? AND expires_at > ?",
                        (now, challenge["id"], OTP_MAX_ATTEMPTS, now),
                    ).rowcount
                    if updated:
                        db.execute("UPDATE users SET email_verified=1 WHERE id=?", (pending_id,))
                        session.pop(EMAIL_VERIFICATION_SESSION_KEY, None)
                        flash("Email verified. You can now log in.", "success")
                        return redirect(url_for("login"))
                    flash("That code is no longer active. Request a new code.", "error")
                else:
                    next_count = challenge["attempt_count"] + 1
                    db.execute(
                        "UPDATE email_verification_otps SET attempt_count=?, invalidated_at=CASE WHEN ? >= ? THEN ? ELSE invalidated_at END WHERE id=? AND used_at IS NULL AND invalidated_at IS NULL",
                        (next_count, next_count, OTP_MAX_ATTEMPTS, now, challenge["id"]),
                    )
                    flash("That verification code is incorrect.", "error")
    return render_template("verify_email.html", email=masked_email(user["email"]))


@app.route("/verify-email/resend", methods=["POST"])
def resend_verification_email():
    registration_id = session.get(PENDING_REGISTRATION_SESSION_KEY)
    if isinstance(registration_id, int):
        with get_db() as db:
            pending = db.execute("SELECT * FROM pending_registrations WHERE id=? AND expires_at>?", (registration_id, utc_now_text())).fetchone()
        if pending is None:
            session.pop(PENDING_REGISTRATION_SESSION_KEY, None)
            flash("This registration has expired. Please register again.", "error")
            return redirect(url_for("register"))
        try:
            sent, message = send_registration_otp(registration_id, pending["full_name"], pending["email"], is_resend=True)
            flash("A new verification code has been sent." if sent else message, "success" if sent else "error")
        except (EmailConfigurationError, EmailDeliveryError, ValueError):
            flash("The verification email could not be sent. Check the email configuration and try again later.", "error")
        return redirect(url_for("verify_email"))

    pending_id = session.get(EMAIL_VERIFICATION_SESSION_KEY)
    if not isinstance(pending_id, int):
        flash("Start by registering or logging in with your account to request a verification code.", "error")
        return redirect(url_for("register"))
    with get_db() as db:
        user = db.execute("SELECT id,full_name,email,email_verified FROM users WHERE id=?", (pending_id,)).fetchone()
    if user is None or user["email_verified"]:
        session.pop(EMAIL_VERIFICATION_SESSION_KEY, None)
        flash("A verification code cannot be sent for this account.", "error")
        return redirect(url_for("login"))
    try:
        sent, message = send_verification_otp(user["id"], user["full_name"], user["email"], is_resend=True)
        flash("A new verification code has been sent." if sent else message, "success" if sent else "error")
    except (EmailConfigurationError, EmailDeliveryError, ValueError):
        flash("The verification email could not be sent. Check the email configuration and try again later.", "error")
    return redirect(url_for("verify_email"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            if not user["email_verified"]:
                session.clear()
                session[EMAIL_VERIFICATION_SESSION_KEY] = user["id"]
                flash("Please verify your email before logging in.", "error")
                return redirect(url_for("verify_email"))
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("root_event_requests") if user["role"] == "root" else url_for("dashboard"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


def current_user():
    with get_db() as db:
        return db.execute("SELECT id,full_name,email,phone,institution,affiliation,role,face_embedding,profile_completed FROM users WHERE id = ?", (session["user_id"],)).fetchone()


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        institution = request.form.get("institution", "").strip()
        affiliation = request.form.get("affiliation", "").strip().lower()
        if not full_name:
            flash("Your name is required.", "error")
        elif not phone or not institution:
            flash("Phone and institute/university are required to complete your profile.", "error")
        elif affiliation not in {"internal", "external"}:
            flash("Choose internal or external affiliation.", "error")
        elif len(full_name) > 120 or len(phone) > 40 or len(institution) > 160:
            flash("One or more profile fields exceed the allowed length.", "error")
        else:
            with get_db() as db:
                db.execute("UPDATE users SET full_name=?,phone=?,institution=?,affiliation=?,profile_completed=1 WHERE id=?",
                           (full_name, phone, institution, affiliation, user["id"]))
            flash("Profile completed." if not user["profile_completed"] else "Profile updated.", "success")
            return redirect(url_for("profile"))
    safe_user = {key:user[key] for key in ("id","full_name","email","phone","institution","affiliation","role","profile_completed")}
    safe_user["face_registered"] = bool(user["face_embedding"])
    return render_template("profile.html", user=safe_user)


def record_request_history(db, item, actor_id, action, root_note=None):
    db.execute(
        """INSERT INTO event_request_history
           (event_request_id,actor_id,action,event_title,description,proposed_date,venue,root_note)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            item["id"], actor_id, action, item["event_title"], item["description"],
            item["proposed_date"], item["venue"],
            item["root_note"] or "" if root_note is None else root_note,
        ),
    )


def submitted_image():
    """Accept either a browser-captured data URL or a normal image upload."""
    payload = request.get_json(silent=True)
    if payload is not None and not isinstance(payload, dict):
        raise FaceError("Invalid captured image.")
    payload = payload or {}
    image_data = payload.get("image_data", "") or request.form.get("image_data", "")
    if image_data:
        if not isinstance(image_data, str) or len(image_data) > app.config["MAX_CONTENT_LENGTH"]:
            raise FaceError("Invalid captured image.")
        match = re.fullmatch(r"data:image/(jpeg|png);base64,([A-Za-z0-9+/=]+)", image_data)
        if not match:
            raise FaceError("Invalid captured image.")
        try:
            return base64.b64decode(match.group(2), validate=True)
        except ValueError as error:
            raise FaceError("Invalid image data.") from error
    upload = request.files.get("image")
    if not upload or not upload.filename or not allowed_image(upload.filename):
        raise FaceError("Choose a JPG or PNG image.")
    return upload.read()


@app.route("/dashboard")
@login_required
def dashboard():
    account = current_user()
    user = {key:account[key] for key in ("id","full_name","email","phone","institution","affiliation","role","profile_completed")}
    user["face_registered"] = bool(account["face_embedding"])
    is_root = user["role"] == "root"
    with get_db() as db:
        event_requests = [] if is_root else db.execute(
            "SELECT * FROM event_requests WHERE requester_id=? ORDER BY requested_at DESC,id DESC", (user["id"],)
        ).fetchall()
        events = [] if is_root else db.execute(
            """SELECT DISTINCT e.* FROM events e LEFT JOIN event_co_conveners cc ON cc.event_id=e.id
               WHERE e.primary_convener_id=? OR cc.user_id=? ORDER BY e.created_at DESC""",
            (user["id"],user["id"]),
        ).fetchall()
        events = [dict(event,status=refresh_event_status(db,event)) for event in events]
        gate_events = [] if is_root else db.execute(
            """SELECT e.id,e.event_name,e.start_date,e.end_date FROM event_gate_staff gs
               JOIN events e ON e.id=gs.event_id WHERE gs.user_id=? ORDER BY e.start_date,e.id""", (user["id"],)
        ).fetchall()
        accommodation_events = [] if is_root else db.execute(
            """SELECT e.id,e.event_name,e.start_date,e.end_date FROM event_accommodation_team at
               JOIN events e ON e.id=at.event_id WHERE at.user_id=? ORDER BY e.start_date,e.id""", (user["id"],)
        ).fetchall()
        my_teams = [] if is_root else db.execute(
            """SELECT t.id,t.team_name,t.event_id,e.event_name,
                      CASE WHEN t.team_leader_id=? THEN 'Team Leader' ELSE 'Member' END AS relation
               FROM event_teams t JOIN events e ON e.id=t.event_id
               LEFT JOIN event_team_members tm ON tm.team_id=t.id AND tm.user_id=?
               WHERE t.team_leader_id=? OR tm.user_id=? ORDER BY e.event_name,t.team_name""",
            (user["id"],user["id"],user["id"],user["id"]),
        ).fetchall()
        my_programs = [] if is_root else db.execute(
            """SELECT DISTINCT p.*,e.event_name,ph.role FROM programs p JOIN events e ON e.id=p.event_id
               JOIN program_hosts ph ON ph.program_id=p.id WHERE ph.user_id=? ORDER BY p.start_at,p.id""",
            (user["id"],),
        ).fetchall()
        my_programs = [dict(program,status=refresh_program_status(db,program)) for program in my_programs]

        registrations = []
        if not is_root:
            raw_registrations = db.execute(
                """SELECT pr.id,pr.user_id,pr.event_id,pr.program_id,pr.participant_type,pr.institute_id,
                          pr.registration_mode,pr.registered_at,p.program_name,p.participation_mode,p.start_at,p.end_at,
                          p.registration_deadline,p.venue,p.fee,p.status,e.event_name,e.start_date,e.end_date
                   FROM participant_registrations pr
                   JOIN programs p ON p.id=pr.program_id AND p.event_id=pr.event_id
                   JOIN events e ON e.id=pr.event_id WHERE pr.user_id=?
                   ORDER BY p.start_at DESC,pr.registered_at DESC,pr.id DESC""", (user["id"],)
            ).fetchall()
            for row in raw_registrations:
                item = dict(row)
                item["status"] = refresh_program_status(db,item)
                item["event_status"] = refresh_event_status(db,{
                    "id":item["event_id"],"start_date":item["start_date"],"end_date":item["end_date"],
                    "status":db.execute("SELECT status FROM events WHERE id=?",(item["event_id"],)).fetchone()[0],
                })
                item["registration_open"] = datetime.now() <= datetime.fromisoformat(item["registration_deadline"])
                item["can_edit"] = registration_can_edit(db,item)
                item["latest_payment"] = db.execute(
                    "SELECT id,status,amount_cents,receipt_number FROM payment_records WHERE registration_id=? ORDER BY id DESC LIMIT 1",
                    (item["id"],),
                ).fetchone()
                item["successful_payment"] = db.execute(
                    "SELECT id,status,amount_cents,receipt_number FROM payment_records WHERE registration_id=? AND status='SUCCESS' ORDER BY id DESC LIMIT 1",
                    (item["id"],),
                ).fetchone()
                item["active_qr_pass"] = db.execute(
                    "SELECT id,pass_number,status FROM qr_passes WHERE registration_id=? AND status='ACTIVE'",
                    (item["id"],),
                ).fetchone()
                item["attendance"] = db.execute(
                    "SELECT verification_method,entered_at FROM attendance_entries WHERE registration_id=? AND program_id=?",
                    (item["id"],item["program_id"]),
                ).fetchone()
                item["accommodation"] = db.execute(
                    """SELECT accommodation_name,room_details,stay_from,stay_until,notes
                       FROM accommodation_allocations WHERE event_id=? AND participant_user_id=?""",
                    (item["event_id"],user["id"]),
                ).fetchone()
                team = db.execute(
                    """SELECT t.id,t.program_id,t.event_id,t.captain_registration_id,t.status,p.team_size,
                              p.program_name,
                              t.captain_registration_id=tm.registration_id AS is_captain
                       FROM participant_team_members tm JOIN participant_teams t ON t.id=tm.team_id
                       JOIN programs p ON p.id=t.program_id AND p.event_id=t.event_id
                       WHERE tm.registration_id=? AND t.status='ACTIVE'""", (item["id"],)
                ).fetchone()
                if team:
                    team = dict(team)
                    team["display_name"] = team["program_name"] + " participant team"
                    team["members"] = db.execute(
                        """SELECT pr.id,pr.full_name,pr.id=t.captain_registration_id AS is_captain
                           FROM participant_team_members tm JOIN participant_registrations pr ON pr.id=tm.registration_id
                           JOIN participant_teams t ON t.id=tm.team_id WHERE t.id=? ORDER BY is_captain DESC,pr.full_name""",
                        (team["id"],),
                    ).fetchall()
                item["participant_team"] = team
                registrations.append(item)
        accommodations = [] if is_root else db.execute(
            """SELECT aa.event_id,e.event_name,aa.accommodation_name,aa.room_details,aa.stay_from,aa.stay_until,aa.notes
               FROM accommodation_allocations aa JOIN events e ON e.id=aa.event_id
               WHERE aa.participant_user_id=? ORDER BY aa.stay_from,aa.id""", (user["id"],)
        ).fetchall()
        my_meetings = [] if is_root else db.execute(
            """SELECT DISTINCT m.id,m.title,m.meeting_date,m.start_time,m.end_time,m.meeting_link,m.event_id,
                      e.event_name,p.program_name FROM meetings m JOIN events e ON e.id=m.event_id
               LEFT JOIN programs p ON p.id=m.program_id
               WHERE EXISTS (SELECT 1 FROM meeting_participants mp JOIN participant_registrations pr
                             ON pr.id=mp.registration_id WHERE mp.meeting_id=m.id AND pr.user_id=?)
                  OR EXISTS (SELECT 1 FROM meeting_teams mt JOIN participant_team_members tm
                             ON tm.team_id=mt.participant_team_id JOIN participant_registrations pr
                             ON pr.id=tm.registration_id WHERE mt.meeting_id=m.id AND pr.user_id=?)
               ORDER BY m.meeting_date,m.start_time,m.id""", (user["id"],user["id"])
        ).fetchall()
    return render_template("dashboard.html", user=user, event_requests=event_requests, events=events,
                           gate_events=gate_events, accommodation_events=accommodation_events,
                           accommodations=accommodations,my_teams=my_teams,my_programs=my_programs,
                           registrations=registrations,my_meetings=my_meetings)


def refresh_event_status(db, event):
    today = date.today().isoformat()
    if today < event["start_date"]:
        status = "UPCOMING"
    elif today > event["end_date"]:
        status = "COMPLETED"
    else:
        status = "ONGOING"
    if event["status"] != status:
        db.execute("UPDATE events SET status = ? WHERE id = ?", (status, event["id"]))
    return status


def refresh_program_status(db, program):
    if program["status"] == "CANCELLED":
        return "CANCELLED"
    now = datetime.now()
    start = datetime.fromisoformat(program["start_at"])
    end = datetime.fromisoformat(program["end_at"])
    if now < start:
        status = "UPCOMING"
    elif now > end:
        status = "COMPLETED"
    else:
        status = "ONGOING"
    if program["status"] != status:
        db.execute("UPDATE programs SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (status, program["id"]))
    return status


def parse_program_form(form):
    values = {
        "program_name": form.get("program_name", "").strip(),
        "description": form.get("description", "").strip(),
        "category": form.get("category", "").strip(),
        "participation_mode": form.get("participation_mode", "").strip().upper(),
        "start_at": form.get("start_at", "").strip(),
        "end_at": form.get("end_at", "").strip(),
        "registration_deadline": form.get("registration_deadline", "").strip(),
        "venue": form.get("venue", "").strip(),
    }
    if not all(values[key] for key in ("program_name", "category", "participation_mode", "start_at", "end_at", "registration_deadline", "venue")):
        return None, "Complete all required program fields."
    if values["participation_mode"] not in {"INDIVIDUAL", "TEAM"}:
        return None, "Choose Individual or Team participation."
    try:
        start = datetime.fromisoformat(values["start_at"])
        end = datetime.fromisoformat(values["end_at"])
        deadline = datetime.fromisoformat(values["registration_deadline"])
    except ValueError:
        return None, "Enter valid program dates and times."
    if start.tzinfo is not None or end.tzinfo is not None or deadline.tzinfo is not None:
        return None, "Use local date and time values."
    if end <= start:
        return None, "Program end time must be after its start time."
    if deadline > start:
        return None, "Registration deadline cannot be after the program start time."
    team_size = None
    if values["participation_mode"] == "TEAM":
        raw_size = form.get("team_size", "").strip()
        try:
            team_size = int(raw_size)
        except ValueError:
            return None, "Team size is required for Team programs."
        if not 2 <= team_size <= 100:
            return None, "Team size must be between 2 and 100."
    try:
        fee = Decimal(form.get("fee", "0").strip() or "0")
    except InvalidOperation:
        return None, "Enter a valid non-negative program fee."
    if not fee.is_finite() or fee < 0:
        return None, "Enter a valid non-negative program fee."
    values.update(team_size=team_size, fee=float(fee))
    return values, None


def get_program_access(db, program_id, user_id):
    return db.execute(
        """SELECT p.*,e.event_name,e.primary_convener_id,e.visibility AS event_visibility,
                  EXISTS(SELECT 1 FROM event_co_conveners cc WHERE cc.event_id=e.id AND cc.user_id=?) AS is_event_convener,
                  EXISTS(SELECT 1 FROM program_hosts ph WHERE ph.program_id=p.id AND ph.user_id=?) AS is_program_host
           FROM programs p JOIN events e ON e.id=p.event_id WHERE p.id=?""",
        (user_id, user_id, program_id),
    ).fetchone()


def can_manage_program(program, user_id):
    return program["primary_convener_id"] == user_id or bool(program["is_event_convener"]) or bool(program["is_program_host"])


def can_manage_event_programs(db, event_id, user_id):
    return db.execute(
        """SELECT 1 FROM events e WHERE e.id=? AND (e.primary_convener_id=? OR EXISTS
           (SELECT 1 FROM event_co_conveners cc WHERE cc.event_id=e.id AND cc.user_id=?))""",
        (event_id, user_id, user_id),
    ).fetchone() is not None


def is_assigned_gate_staff(db, event_id, user_id):
    return db.execute(
        "SELECT 1 FROM event_gate_staff WHERE event_id=? AND user_id=?",
        (event_id, user_id),
    ).fetchone() is not None


def is_assigned_accommodation_staff(db, event_id, user_id):
    return db.execute(
        "SELECT 1 FROM event_accommodation_team WHERE event_id=? AND user_id=?",
        (event_id, user_id),
    ).fetchone() is not None


def accommodation_event_access(db, event_id, user):
    if user["role"] == "root":
        abort(403)
    event = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if event is None:
        abort(404)
    if not (can_manage_event_programs(db, event_id, user["id"])
            or is_assigned_accommodation_staff(db, event_id, user["id"])):
        abort(403)
    return event


def parse_accommodation_form(form):
    values = {
        "accommodation_name": form.get("accommodation_name", "").strip(),
        "room_details": form.get("room_details", "").strip(),
        "stay_from": form.get("stay_from", "").strip(),
        "stay_until": form.get("stay_until", "").strip(),
        "notes": form.get("notes", "").strip(),
    }
    if not values["accommodation_name"] or not values["room_details"]:
        return None, "Accommodation name and room details are required."
    if len(values["accommodation_name"]) > 160 or len(values["room_details"]) > 120 or len(values["notes"]) > 1000:
        return None, "Accommodation or room details are too long. Notes must be 1000 characters or less."
    try:
        start = date.fromisoformat(values["stay_from"])
        end = date.fromisoformat(values["stay_until"])
    except ValueError:
        return None, "Enter valid stay dates."
    if end < start:
        return None, "Stay-until date cannot be before stay-from date."
    return values, None


def lookup_qr_pass(db, event_id, program_id, token):
    """Resolve a raw pass token using the Phase 9 hash and context checks."""
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return db.execute(
        """SELECT q.*,pr.full_name,pr.id AS valid_registration_id,
                  p.program_name,p.status AS program_status,e.event_name
           FROM qr_passes q
           JOIN participant_registrations pr
             ON pr.id=q.registration_id AND pr.program_id=q.program_id AND pr.event_id=q.event_id
           JOIN programs p ON p.id=q.program_id AND p.event_id=q.event_id
           JOIN events e ON e.id=q.event_id
           WHERE q.token_hash=? AND q.event_id=? AND q.program_id=?""",
        (token_hash, event_id, program_id),
    ).fetchone()


def active_qr_pass(db, event_id, program_id, token):
    pass_record = lookup_qr_pass(db, event_id, program_id, token)
    program = db.execute("SELECT * FROM programs WHERE id=? AND event_id=?", (program_id, event_id)).fetchone()
    if (pass_record is None or pass_record["registration_id"] != pass_record["valid_registration_id"]
            or pass_record["status"] != "ACTIVE" or program is None
            or refresh_program_status(db, program) == "CANCELLED"):
        return None
    return pass_record


@app.route("/events")
def public_events():
    with get_db() as db:
        events = db.execute("SELECT * FROM events WHERE visibility = 'PUBLIC' ORDER BY start_date, id").fetchall()
        events = [dict(event, status=refresh_event_status(db, event)) for event in events]
    return render_template("events_public.html", events=events)


def get_managed_event(db, event_id, user_id):
    return db.execute(
        """SELECT e.* FROM events e
           WHERE e.id = ? AND (e.primary_convener_id = ? OR EXISTS
             (SELECT 1 FROM event_co_conveners cc WHERE cc.event_id = e.id AND cc.user_id = ?))""",
        (event_id, user_id, user_id),
    ).fetchone()


def load_meeting_form_data(db, event_id, program_id=None):
    programs = db.execute("SELECT id,program_name FROM programs WHERE event_id=? ORDER BY start_at,id", (event_id,)).fetchall()
    recipient_groups = []
    convener_count = db.execute(
        "SELECT 1 + COUNT(*) FROM event_co_conveners WHERE event_id=?", (event_id,)
    ).fetchone()[0]
    if convener_count:
        recipient_groups.append({"group_type": "CONVENERS", "label": "Convener Group", "member_count": convener_count})
    group_sources = (
        ("GATE_STAFF", "Gate Staff", "event_gate_staff"),
        ("ACCOMMODATION_TEAM", "Accommodation Team", "event_accommodation_team"),
    )
    for group_type, label, table_name in group_sources:
        count = db.execute(f"SELECT COUNT(*) FROM {table_name} WHERE event_id=?", (event_id,)).fetchone()[0]
        if count:
            recipient_groups.append({"group_type": group_type, "label": label, "member_count": count})
    host_query = """SELECT COUNT(DISTINCT ph.user_id) FROM program_hosts ph
                    JOIN programs p ON p.id=ph.program_id WHERE p.event_id=?"""
    host_params = (event_id,)
    if program_id is not None:
        host_query += " AND ph.program_id=?"
        host_params = (event_id, program_id)
    host_count = db.execute(host_query, host_params).fetchone()[0]
    if host_count:
        recipient_groups.append({"group_type": "PROGRAM_HOSTS", "label": "Program Hosts", "member_count": host_count})
    event_teams = db.execute(
        """SELECT t.id,t.team_name,t.description,u.full_name AS team_leader_name,
                  (SELECT COUNT(DISTINCT tm.user_id) FROM event_team_members tm WHERE tm.team_id=t.id)
                    + CASE WHEN EXISTS (SELECT 1 FROM event_team_members tm WHERE tm.team_id=t.id AND tm.user_id=t.team_leader_id)
                           THEN 0 ELSE 1 END AS member_count
           FROM event_teams t JOIN users u ON u.id=t.team_leader_id
           WHERE t.event_id=? ORDER BY t.team_name COLLATE NOCASE,t.id""", (event_id,)
    ).fetchall()
    return programs, recipient_groups, event_teams


def parse_meeting_values(form):
    values = {key: form.get(key, "").strip() for key in
              ("title", "description", "meeting_date", "start_time", "end_time", "meeting_link", "program_id")}
    if not all(values[key] for key in ("title", "meeting_date", "start_time", "end_time", "meeting_link")):
        return None, "Complete the meeting title, date, times, and external meeting link."
    try:
        date.fromisoformat(values["meeting_date"])
        start = datetime.strptime(values["start_time"], "%H:%M").time()
        end = datetime.strptime(values["end_time"], "%H:%M").time()
    except ValueError:
        return None, "Enter a valid meeting date and time."
    if end <= start:
        return None, "Meeting end time must be after its start time."
    if len(values["title"]) > 160 or len(values["description"]) > 4000:
        return None, "The meeting title or agenda is too long."
    if len(values["meeting_link"]) > 1000:
        return None, "The meeting link is too long."
    from urllib.parse import urlparse
    parsed_link = urlparse(values["meeting_link"])
    if parsed_link.scheme not in {"http", "https"} or not parsed_link.netloc:
        return None, "Enter a complete http or https meeting link."
    program_id = None
    if values["program_id"]:
        try:
            program_id = int(values["program_id"])
        except ValueError:
            return None, "Choose a valid program."
    values["program_id"] = program_id
    return values, None


def replace_meeting_recipients(db, meeting_id, event_id, program_id, form):
    group_types = set(form.getlist("internal_group_types"))
    event_team_ids = set()
    try:
        event_team_ids = {int(value) for value in form.getlist("event_team_ids")}
    except ValueError:
        return "Choose valid event management teams."
    _, available_groups, available_teams = load_meeting_form_data(db, event_id, program_id)
    if group_types - {item["group_type"] for item in available_groups}:
        return "Choose an internal group assigned to this event."
    available_team_ids = {team["id"] for team in available_teams}
    if event_team_ids - available_team_ids:
        return "Event management teams must belong to this event."
    # Stop using legacy participant recipient links for meetings edited under the internal-team workflow.
    db.execute("DELETE FROM meeting_participants WHERE meeting_id=?", (meeting_id,))
    db.execute("DELETE FROM meeting_teams WHERE meeting_id=?", (meeting_id,))
    db.execute("DELETE FROM meeting_internal_group_recipients WHERE meeting_id=?", (meeting_id,))
    db.execute("DELETE FROM meeting_event_teams WHERE meeting_id=?", (meeting_id,))
    db.executemany(
        "INSERT INTO meeting_internal_group_recipients(meeting_id,event_id,group_type) VALUES (?,?,?)",
        [(meeting_id, event_id, group_type) for group_type in sorted(group_types)],
    )
    db.executemany(
        "INSERT INTO meeting_event_teams(meeting_id,event_id,event_team_id) VALUES (?,?,?)",
        [(meeting_id, event_id, team_id) for team_id in sorted(event_team_ids)],
    )
    return None


def meeting_recipient_addresses(db, meeting_id):
    rows = db.execute(
        """SELECT DISTINCT u.email FROM meeting_internal_group_recipients r
           JOIN events e ON e.id=r.event_id
           JOIN users u ON u.id=e.primary_convener_id
           WHERE r.meeting_id=? AND r.group_type='CONVENERS'
           UNION
           SELECT DISTINCT u.email FROM meeting_internal_group_recipients r
           JOIN event_co_conveners cc ON cc.event_id=r.event_id
           JOIN users u ON u.id=cc.user_id
           WHERE r.meeting_id=? AND r.group_type='CONVENERS'
           UNION
           SELECT DISTINCT u.email FROM meeting_internal_group_recipients r
           JOIN event_gate_staff gs ON gs.event_id=r.event_id
           JOIN users u ON u.id=gs.user_id
           WHERE r.meeting_id=? AND r.group_type='GATE_STAFF'
           UNION
           SELECT DISTINCT u.email FROM meeting_internal_group_recipients r
           JOIN event_accommodation_team at ON at.event_id=r.event_id
           JOIN users u ON u.id=at.user_id
           WHERE r.meeting_id=? AND r.group_type='ACCOMMODATION_TEAM'
           UNION
           SELECT DISTINCT u.email FROM meeting_internal_group_recipients r
           JOIN program_hosts ph ON ph.role IN ('HOST','CO_HOST')
           JOIN programs p ON p.id=ph.program_id AND p.event_id=r.event_id
           JOIN users u ON u.id=ph.user_id
           JOIN meetings m ON m.id=r.meeting_id AND m.event_id=r.event_id
           WHERE r.meeting_id=? AND r.group_type='PROGRAM_HOSTS'
             AND (m.program_id IS NULL OR p.id=m.program_id)
           UNION
           SELECT DISTINCT u.email FROM meeting_event_teams mt
           JOIN event_teams t ON t.id=mt.event_team_id AND t.event_id=mt.event_id
           JOIN users u ON u.id=t.team_leader_id
           WHERE mt.meeting_id=?
           UNION
           SELECT DISTINCT u.email FROM meeting_event_teams mt
           JOIN event_team_members tm ON tm.team_id=mt.event_team_id
           JOIN users u ON u.id=tm.user_id
           WHERE mt.meeting_id=?""",
        (meeting_id, meeting_id, meeting_id, meeting_id, meeting_id, meeting_id, meeting_id),
    ).fetchall()
    return [row["email"] for row in rows]


def format_meeting_email(meeting):
    parsed_day = date.fromisoformat(meeting["meeting_date"])
    day = f"{parsed_day.day} {parsed_day.strftime('%B %Y')}"
    start = datetime.strptime(meeting["start_time"], "%H:%M").strftime("%I:%M %p").lstrip("0")
    end = datetime.strptime(meeting["end_time"], "%H:%M").strftime("%I:%M %p").lstrip("0")
    return (f"Meeting Scheduled\n\nEvent: {meeting['event_name']}\n"
            f"Program: {meeting['program_name'] or 'Event-level meeting'}\n"
            f"Meeting: {meeting['title']}\nDate: {day}\nTime: {start} – {end}\n\n"
            f"Agenda:\n{meeting['description'] or 'No agenda provided.'}\n\n"
            f"Join Meeting:\n{meeting['meeting_link']}\n")


def meeting_management_access(db, event_id, user):
    if user["role"] == "root":
        abort(403)
    event = get_managed_event(db, event_id, user["id"])
    if event is None:
        abort(403)
    return event


def meeting_with_context(db, meeting_id):
    return db.execute(
        """SELECT m.*,e.event_name,p.program_name FROM meetings m
           JOIN events e ON e.id=m.event_id LEFT JOIN programs p ON p.id=m.program_id
           WHERE m.id=?""", (meeting_id,)
    ).fetchone()


def render_meeting_form(db, event, meeting=None, program_id=None):
    selected_group_types, selected_event_teams = set(), set()
    if meeting:
        selected_group_types = {row[0] for row in db.execute("SELECT group_type FROM meeting_internal_group_recipients WHERE meeting_id=?", (meeting["id"],))}
        selected_event_teams = {row[0] for row in db.execute("SELECT event_team_id FROM meeting_event_teams WHERE meeting_id=?", (meeting["id"],))}
    selected_program_id = meeting["program_id"] if meeting else program_id
    programs, recipient_groups, event_teams = load_meeting_form_data(db, event["id"], selected_program_id)
    return render_template("meeting_form.html", event=event, meeting=meeting, programs=programs,
                           recipient_groups=recipient_groups, event_teams=event_teams,
                           selected_group_types=selected_group_types, selected_event_teams=selected_event_teams)


@app.route("/convener/events/<int:event_id>/meetings")
@login_required
def event_meetings(event_id):
    user = current_user()
    with get_db() as db:
        event = meeting_management_access(db, event_id, user)
        meetings = db.execute(
            """SELECT m.*,p.program_name,
                      (SELECT COUNT(*) FROM meeting_internal_group_recipients gr WHERE gr.meeting_id=m.id) AS group_count,
                      (SELECT COUNT(*) FROM meeting_event_teams et WHERE et.meeting_id=m.id) AS team_count
               FROM meetings m LEFT JOIN programs p ON p.id=m.program_id
               WHERE m.event_id=? ORDER BY m.meeting_date,m.start_time,m.id""", (event_id,)
        ).fetchall()
    return render_template("meetings.html", event=event, meetings=meetings)


@app.route("/convener/events/<int:event_id>/meetings/new", methods=["GET", "POST"])
@login_required
def create_meeting(event_id):
    user = current_user()
    with get_db() as db:
        event = meeting_management_access(db, event_id, user)
        if request.method == "GET":
            return render_meeting_form(db, event)
        values, error = parse_meeting_values(request.form)
        if error:
            flash(error, "error")
            return render_meeting_form(db, event)
        if values["program_id"] is not None and db.execute("SELECT 1 FROM programs WHERE id=? AND event_id=?", (values["program_id"], event_id)).fetchone() is None:
            flash("The selected program does not belong to this event.", "error")
            return render_meeting_form(db, event)
        cursor = db.execute(
            """INSERT INTO meetings(event_id,program_id,title,description,meeting_date,start_time,end_time,meeting_link,created_by)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (event_id, values["program_id"], values["title"], values["description"], values["meeting_date"],
             values["start_time"], values["end_time"], values["meeting_link"], user["id"]),
        )
        issue = replace_meeting_recipients(db, cursor.lastrowid, event_id, values["program_id"], request.form)
        if issue:
            db.rollback()
            flash(issue, "error")
            return render_meeting_form(db, event, program_id=values["program_id"])
        flash("Meeting created.", "success")
        return redirect(url_for("event_meetings", event_id=event_id))


@app.route("/meetings/<int:meeting_id>/edit", methods=["GET", "POST"])
@login_required
def edit_meeting(meeting_id):
    user = current_user()
    with get_db() as db:
        meeting = meeting_with_context(db, meeting_id)
        if meeting is None:
            abort(404)
        event = meeting_management_access(db, meeting["event_id"], user)
        if request.method == "GET":
            return render_meeting_form(db, event, meeting)
        values, error = parse_meeting_values(request.form)
        if error:
            flash(error, "error")
            return render_meeting_form(db, event, meeting)
        if values["program_id"] is not None and db.execute("SELECT 1 FROM programs WHERE id=? AND event_id=?", (values["program_id"], event["id"])).fetchone() is None:
            flash("The selected program does not belong to this event.", "error")
            return render_meeting_form(db, event, meeting)
        db.execute(
            """UPDATE meetings SET program_id=?,title=?,description=?,meeting_date=?,start_time=?,end_time=?,meeting_link=?,updated_at=CURRENT_TIMESTAMP
               WHERE id=? AND event_id=?""",
            (values["program_id"], values["title"], values["description"], values["meeting_date"],
             values["start_time"], values["end_time"], values["meeting_link"], meeting_id, event["id"]),
        )
        issue = replace_meeting_recipients(db, meeting_id, event["id"], values["program_id"], request.form)
        if issue:
            db.rollback()
            flash(issue, "error")
            return render_meeting_form(db, event, meeting, values["program_id"])
        flash("Meeting updated.", "success")
        return redirect(url_for("event_meetings", event_id=event["id"]))


@app.route("/meetings/<int:meeting_id>/delete", methods=["POST"])
@login_required
def delete_meeting(meeting_id):
    user = current_user()
    with get_db() as db:
        meeting = meeting_with_context(db, meeting_id)
        if meeting is None:
            abort(404)
        meeting_management_access(db, meeting["event_id"], user)
        db.execute("DELETE FROM meetings WHERE id=?", (meeting_id,))
    flash("Meeting deleted.", "success")
    return redirect(url_for("event_meetings", event_id=meeting["event_id"]))


@app.route("/meetings/<int:meeting_id>/send", methods=["POST"])
@login_required
def send_meeting_invitation(meeting_id):
    user = current_user()
    with get_db() as db:
        meeting = meeting_with_context(db, meeting_id)
        if meeting is None:
            abort(404)
        meeting_management_access(db, meeting["event_id"], user)
        recipients = meeting_recipient_addresses(db, meeting_id)
        if not recipients:
            flash("Add at least one internal event group or event management team before sending.", "error")
            return redirect(url_for("event_meetings", event_id=meeting["event_id"]))
        try:
            send_email(f"Meeting Scheduled: {meeting['title']}", format_meeting_email(meeting), [], bcc=recipients)
        except (EmailConfigurationError, EmailDeliveryError, ValueError) as error:
            flash(str(error), "error")
            return redirect(url_for("event_meetings", event_id=meeting["event_id"]))
    flash(f"Meeting invitation sent to {len(recipients)} event staff member(s).", "success")
    return redirect(url_for("event_meetings", event_id=meeting["event_id"]))


@app.route("/meetings/<int:meeting_id>")
@login_required
def participant_meeting_detail(meeting_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    with get_db() as db:
        meeting = meeting_with_context(db, meeting_id)
        if meeting is None:
            abort(404)
        allowed = db.execute(
            """SELECT 1 FROM participant_registrations pr WHERE pr.user_id=? AND (
                 EXISTS (SELECT 1 FROM meeting_participants mp WHERE mp.meeting_id=? AND mp.registration_id=pr.id)
                 OR EXISTS (SELECT 1 FROM meeting_teams mt JOIN participant_team_members tm
                            ON tm.team_id=mt.participant_team_id WHERE mt.meeting_id=? AND tm.registration_id=pr.id))
               LIMIT 1""", (user["id"], meeting_id, meeting_id)
        ).fetchone()
        if allowed is None:
            abort(403)
    return render_template("meeting_detail.html", meeting=meeting)


def primary_owned_event(db, event_id, user_id):
    return db.execute("SELECT * FROM events WHERE id = ? AND primary_convener_id = ?", (event_id, user_id)).fetchone()


@app.route("/events/<int:event_id>")
def public_event_detail(event_id):
    with get_db() as db:
        event = db.execute("SELECT * FROM events WHERE id = ? AND visibility = 'PUBLIC'", (event_id,)).fetchone()
        if event is None:
            abort(404)
        event = dict(event, status=refresh_event_status(db, event))
        programs = db.execute("SELECT * FROM programs WHERE event_id=? ORDER BY start_at,id", (event_id,)).fetchall()
        programs = [dict(program, status=refresh_program_status(db, program)) for program in programs]
    return render_template("event_public_detail.html", event=event, programs=programs)


@app.route("/convener/events/<int:event_id>", methods=["GET", "POST"])
@login_required
def convener_event_dashboard(event_id):
    user = current_user()
    with get_db() as db:
        event = get_managed_event(db, event_id, user["id"])
        if event is None:
            abort(404)
        is_primary = event["primary_convener_id"] == user["id"]
        if request.method == "POST":
            values = {key: request.form.get(key, "").strip() for key in ("event_name", "organization_university", "event_type", "description", "start_date", "end_date", "venue", "visibility")}
            try:
                start_date = date.fromisoformat(values["start_date"])
                end_date = date.fromisoformat(values["end_date"])
            except ValueError:
                flash("Choose valid event dates.", "error")
            else:
                if not all(values[key] for key in ("event_name", "organization_university", "event_type", "description", "venue")) or end_date < start_date or values["visibility"] not in {"PUBLIC", "PRIVATE"}:
                    flash("Complete all fields, choose a valid visibility, and ensure the end date is not before the start date.", "error")
                else:
                    result = db.execute("""UPDATE events SET event_name=?, organization_university=?, event_type=?, description=?, start_date=?, end_date=?, venue=?, visibility=?
                                          WHERE id=? AND (primary_convener_id=? OR EXISTS
                                            (SELECT 1 FROM event_co_conveners cc WHERE cc.event_id=events.id AND cc.user_id=?))""",
                                        (*[values[key] for key in ("event_name", "organization_university", "event_type", "description", "start_date", "end_date", "venue", "visibility")], event_id, user["id"], user["id"]))
                    if result.rowcount == 0:
                        abort(404)
                    updated = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
                    refresh_event_status(db, updated)
                    flash("Event details updated.", "success")
                    return redirect(url_for("convener_event_dashboard", event_id=event_id))
            event = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        status = refresh_event_status(db, event)
        event = dict(event, status=status)
        co_conveners = []
        if is_primary:
            co_conveners = db.execute(
                """SELECT u.id,u.full_name,u.email,cc.assigned_at FROM event_co_conveners cc
                   JOIN users u ON u.id=cc.user_id WHERE cc.event_id=? ORDER BY u.full_name,u.id""",
                (event_id,),
            ).fetchall()
        gate_staff = db.execute(
            """SELECT u.id,u.full_name,u.email,gs.assigned_at FROM event_gate_staff gs
               JOIN users u ON u.id=gs.user_id WHERE gs.event_id=? ORDER BY u.full_name,u.id""",
            (event_id,),
        ).fetchall()
        accommodation_team = db.execute(
            """SELECT u.id,u.full_name,u.email,at.assigned_at FROM event_accommodation_team at
               JOIN users u ON u.id=at.user_id WHERE at.event_id=? ORDER BY u.full_name,u.id""",
            (event_id,),
        ).fetchall()
        teams = db.execute(
            """SELECT t.id,t.team_name,t.description,t.team_leader_id,t.created_at,u.full_name AS leader_name,
                      (SELECT COUNT(*) FROM event_team_members tm WHERE tm.team_id=t.id) AS member_count
               FROM event_teams t JOIN users u ON u.id=t.team_leader_id
               WHERE t.event_id=? ORDER BY t.team_name COLLATE NOCASE,t.id""",
            (event_id,),
        ).fetchall()
        programs = db.execute("SELECT * FROM programs WHERE event_id=? ORDER BY start_at,id", (event_id,)).fetchall()
        programs = [dict(program, status=refresh_program_status(db, program)) for program in programs]
        meetings = db.execute(
            """SELECT m.*,p.program_name FROM meetings m LEFT JOIN programs p ON p.id=m.program_id
               WHERE m.event_id=? ORDER BY m.meeting_date,m.start_time,m.id""", (event_id,)
        ).fetchall()
    return render_template("event_dashboard.html", event=event, is_primary=is_primary, co_conveners=co_conveners,
                           teams=teams, programs=programs, gate_staff=gate_staff,
                           accommodation_team=accommodation_team, meetings=meetings)


@app.route("/convener/events/<int:event_id>/gate-staff", methods=["POST"])
@login_required
def manage_gate_staff(event_id):
    user = current_user()
    action = request.form.get("action", "assign")
    with get_db() as db:
        if not can_manage_event_programs(db, event_id, user["id"]):
            abort(404)
        if action == "remove":
            try:
                staff_id = int(request.form.get("user_id", ""))
            except ValueError:
                abort(400)
            result = db.execute("DELETE FROM event_gate_staff WHERE event_id=? AND user_id=?", (event_id, staff_id))
            flash("Gate Staff removed." if result.rowcount else "That Gate Staff assignment was not found.",
                  "success" if result.rowcount else "error")
        elif action == "assign":
            email = request.form.get("email", "").strip().lower()
            staff = db.execute("SELECT id,role FROM users WHERE email=?", (email,)).fetchone()
            if not email or staff is None or staff["role"] != "user":
                flash("Choose an existing non-Root user as Gate Staff.", "error")
            else:
                try:
                    db.execute("INSERT INTO event_gate_staff(event_id,user_id) VALUES(?,?)", (event_id, staff["id"]))
                    flash("Gate Staff assigned.", "success")
                except sqlite3.IntegrityError:
                    flash("That user is already assigned as Gate Staff.", "error")
        else:
            abort(400)
    return redirect(url_for("convener_event_dashboard", event_id=event_id))


@app.route("/convener/events/<int:event_id>/accommodation-team", methods=["POST"])
@login_required
def manage_accommodation_team(event_id):
    user = current_user()
    action = request.form.get("action", "assign")
    with get_db() as db:
        if user["role"] == "root" or not can_manage_event_programs(db, event_id, user["id"]):
            abort(403)
        if action == "remove":
            try:
                member_id = int(request.form.get("user_id", ""))
            except ValueError:
                abort(400)
            result = db.execute(
                "DELETE FROM event_accommodation_team WHERE event_id=? AND user_id=?",
                (event_id, member_id),
            )
            flash("Accommodation Team member removed." if result.rowcount else "That assignment was not found.",
                  "success" if result.rowcount else "error")
        elif action == "assign":
            email = request.form.get("email", "").strip().lower()
            member = db.execute("SELECT id,role FROM users WHERE email=?", (email,)).fetchone() if email else None
            if member is None or member["role"] != "user":
                flash("Choose an existing non-Root user as an Accommodation Team member.", "error")
            else:
                try:
                    db.execute(
                        "INSERT INTO event_accommodation_team(event_id,user_id) VALUES(?,?)",
                        (event_id, member["id"]),
                    )
                    flash("Accommodation Team member assigned.", "success")
                except sqlite3.IntegrityError:
                    flash("That user is already on this event's Accommodation Team.", "error")
        else:
            abort(400)
    return redirect(url_for("convener_event_dashboard", event_id=event_id))


@app.route("/accommodation/events/<int:event_id>")
@login_required
def accommodation_event(event_id):
    user = current_user()
    with get_db() as db:
        event = accommodation_event_access(db, event_id, user)
        participants = db.execute(
            """SELECT pr.user_id,pr.id AS registration_id,pr.full_name,pr.email,pr.accommodation_required,
                      aa.id AS allocation_id,aa.accommodation_name,
                      aa.room_details,aa.stay_from,aa.stay_until,aa.notes,aa.allocated_by_user_id,
                      aa.created_at,aa.updated_at,allocator.full_name AS allocated_by_name
               FROM participant_registrations pr
               JOIN participant_registrations first_registration
                 ON first_registration.id=(SELECT candidate.id FROM participant_registrations candidate
                   WHERE candidate.event_id=pr.event_id AND candidate.user_id=pr.user_id
                   ORDER BY candidate.accommodation_required DESC,candidate.registered_at,candidate.id LIMIT 1)
               LEFT JOIN accommodation_allocations aa
                 ON aa.event_id=pr.event_id AND aa.participant_user_id=pr.user_id
               LEFT JOIN users allocator ON allocator.id=aa.allocated_by_user_id
               WHERE pr.event_id=? AND pr.id=first_registration.id
               ORDER BY pr.full_name COLLATE NOCASE,pr.user_id""",
            (event_id,),
        ).fetchall()
    return render_template("accommodation_event.html", event=event, participants=participants)


@app.route("/accommodation/events/<int:event_id>/allocations", methods=["POST"])
@login_required
def create_accommodation_allocation(event_id):
    user = current_user()
    with get_db() as db:
        accommodation_event_access(db, event_id, user)
        try:
            participant_id = int(request.form.get("user_id", ""))
        except ValueError:
            abort(400)
        values, error = parse_accommodation_form(request.form)
        registration = db.execute(
            """SELECT id FROM participant_registrations
               WHERE event_id=? AND user_id=? AND accommodation_required=1
               ORDER BY registered_at,id LIMIT 1""",
            (event_id, participant_id),
        ).fetchone()
        if error:
            flash(error, "error")
        elif registration is None:
            flash("This participant has not requested accommodation.", "error")
        elif db.execute(
            "SELECT 1 FROM accommodation_allocations WHERE event_id=? AND participant_user_id=?",
            (event_id, participant_id),
        ).fetchone():
            flash("This participant already has an allocation. Edit the existing record instead.", "error")
        else:
            try:
                db.execute(
                    """INSERT INTO accommodation_allocations
                       (event_id,registration_id,participant_user_id,accommodation_name,room_details,
                        stay_from,stay_until,notes,allocated_by_user_id)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (event_id, registration["id"], participant_id, values["accommodation_name"],
                     values["room_details"], values["stay_from"], values["stay_until"],
                     values["notes"], user["id"]),
                )
                flash("Accommodation allocation saved.", "success")
            except sqlite3.IntegrityError:
                flash("An allocation already exists for this participant in this event.", "error")
    return redirect(url_for("accommodation_event", event_id=event_id))


@app.route("/accommodation/events/<int:event_id>/allocations/<int:allocation_id>/edit", methods=["POST"])
@login_required
def edit_accommodation_allocation(event_id, allocation_id):
    user = current_user()
    with get_db() as db:
        accommodation_event_access(db, event_id, user)
        allocation = db.execute(
            "SELECT id FROM accommodation_allocations WHERE id=? AND event_id=?",
            (allocation_id, event_id),
        ).fetchone()
        if allocation is None:
            abort(404)
        values, error = parse_accommodation_form(request.form)
        if error:
            flash(error, "error")
        else:
            db.execute(
                """UPDATE accommodation_allocations SET accommodation_name=?,room_details=?,stay_from=?,
                   stay_until=?,notes=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND event_id=?""",
                (values["accommodation_name"], values["room_details"], values["stay_from"],
                 values["stay_until"], values["notes"], allocation_id, event_id),
            )
            flash("Accommodation allocation updated.", "success")
    return redirect(url_for("accommodation_event", event_id=event_id))


@app.route("/accommodation/events/<int:event_id>/allocations/<int:allocation_id>/remove", methods=["POST"])
@login_required
def remove_accommodation_allocation(event_id, allocation_id):
    user = current_user()
    with get_db() as db:
        accommodation_event_access(db, event_id, user)
        result = db.execute(
            "DELETE FROM accommodation_allocations WHERE id=? AND event_id=?",
            (allocation_id, event_id),
        )
        if not result.rowcount:
            abort(404)
        flash("Accommodation allocation removed.", "success")
    return redirect(url_for("accommodation_event", event_id=event_id))


def gate_program_access(db, event_id, program_id, user_id):
    if not is_assigned_gate_staff(db, event_id, user_id):
        abort(403)
    return db.execute(
        "SELECT p.*,e.event_name FROM programs p JOIN events e ON e.id=p.event_id WHERE p.id=? AND p.event_id=?",
        (program_id, event_id),
    ).fetchone()


@app.route("/gate/events/<int:event_id>")
@login_required
def gate_event(event_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    with get_db() as db:
        if not is_assigned_gate_staff(db, event_id, user["id"]):
            abort(403)
        event = db.execute("SELECT id,event_name FROM events WHERE id=?", (event_id,)).fetchone()
        if event is None:
            abort(404)
        programs = db.execute("SELECT * FROM programs WHERE event_id=? ORDER BY start_at,id", (event_id,)).fetchall()
        programs = [dict(program, status=refresh_program_status(db, program)) for program in programs]
    return render_template("gate_event.html", event=event, programs=programs)


@app.route("/gate/events/<int:event_id>/programs/<int:program_id>")
@login_required
def gate_program(event_id, program_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    with get_db() as db:
        program = gate_program_access(db, event_id, program_id, user["id"])
        if program is None:
            abort(404)
        status = refresh_program_status(db, program)
        attendance = db.execute(
            "SELECT COUNT(*) AS total FROM attendance_entries WHERE event_id=? AND program_id=?",
            (event_id, program_id),
        ).fetchone()["total"]
    return render_template("gate_program.html", program=dict(program, status=status), attendance=attendance)


def gate_result(status, message, http_status=200, **details):
    return jsonify(status=status, message=message, **details), http_status


def record_gate_entry(db, event_id, program_id, registration_id, method, staff_id):
    existing = db.execute(
        "SELECT entered_at,verification_method FROM attendance_entries WHERE registration_id=? AND program_id=?",
        (registration_id, program_id),
    ).fetchone()
    if existing:
        return existing
    try:
        db.execute(
            """INSERT INTO attendance_entries(event_id,program_id,registration_id,verification_method,gate_staff_user_id)
               VALUES(?,?,?,?,?)""",
            (event_id, program_id, registration_id, method, staff_id),
        )
    except sqlite3.IntegrityError:
        return db.execute(
            "SELECT entered_at,verification_method FROM attendance_entries WHERE registration_id=? AND program_id=?",
            (registration_id, program_id),
        ).fetchone()
    return None


@app.route("/gate/events/<int:event_id>/programs/<int:program_id>/verify-qr", methods=["POST"])
@login_required
def gate_verify_qr(event_id, program_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    token = str(request.form.get("token", "")).strip()
    if not token:
        qr_upload = request.files.get("qr_image")
        if qr_upload and qr_upload.filename and allowed_image(qr_upload.filename):
            try:
                image = cv2.imdecode(np.frombuffer(qr_upload.read(), dtype=np.uint8), cv2.IMREAD_COLOR)
                token, _, _ = cv2.QRCodeDetector().detectAndDecode(image) if image is not None else ("", None, None)
            except cv2.error:
                token = ""
        if not token:
            return gate_result("INVALID", "Enter the pass token or upload a clear QR image.", 400)
    if not token or len(token) > 256:
        return gate_result("INVALID", "Enter a valid QR pass token.", 400)
    with get_db() as db:
        program = gate_program_access(db, event_id, program_id, user["id"])
        if program is None:
            abort(404)
        program_status = refresh_program_status(db, program)
        if program_status == "CANCELLED":
            return gate_result("INVALID", "Cancelled programs cannot admit participants.", 400)
        pass_record = active_qr_pass(db, event_id, program_id, token)
        if pass_record is None:
            return gate_result("INVALID", "QR pass is invalid for this event/program or has been revoked.", 400)
        existing = record_gate_entry(db, event_id, program_id, pass_record["registration_id"], "QR", user["id"])
        if existing:
            return gate_result("ALREADY_ENTERED", "This participant has already entered.", 409,
                               participant=pass_record["full_name"], entered_at=existing["entered_at"])
        return gate_result("ENTERED", "Entry verified and recorded.", participant=pass_record["full_name"],
                           event=pass_record["event_name"], program=pass_record["program_name"], method="QR")


@app.route("/gate/events/<int:event_id>/programs/<int:program_id>/verify-face", methods=["POST"])
@login_required
def gate_verify_face(event_id, program_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    with get_db() as db:
        program = gate_program_access(db, event_id, program_id, user["id"])
        if program is None:
            abort(404)
        if refresh_program_status(db, program) == "CANCELLED":
            return gate_result("INVALID", "Cancelled programs cannot admit participants.", 400)
        try:
            probe = generate_embedding(submitted_image())
        except (FaceError, RuntimeError, ValueError) as error:
            return gate_result("FACE_ERROR", str(error), 400)
        candidates = db.execute(
            """SELECT pr.id AS registration_id,pr.full_name,u.face_embedding FROM participant_registrations pr
               JOIN users u ON u.id=pr.user_id
               WHERE pr.event_id=? AND pr.program_id=? AND u.role='user' AND u.face_embedding IS NOT NULL""",
            (event_id, program_id),
        ).fetchall()
        best = None
        for candidate in candidates:
            try:
                score, matched = compare_embeddings(json.loads(candidate["face_embedding"]), probe)
            except (FaceError, ValueError, TypeError):
                continue
            if best is None or score > best["similarity"]:
                best = {"registration_id": candidate["registration_id"], "full_name": candidate["full_name"],
                        "similarity": score, "matched": matched}
        if best is None or not best["matched"]:
            return gate_result("NO_MATCH", "No registered participant matched this face.",
                               similarity=best["similarity"] if best else None,
                               threshold=SIMILARITY_THRESHOLD)
        existing = record_gate_entry(db, event_id, program_id, best["registration_id"], "FACE", user["id"])
        if existing:
            return gate_result("ALREADY_ENTERED", "This participant has already entered.", 409,
                               participant=best["full_name"], entered_at=existing["entered_at"],
                               similarity=best["similarity"], threshold=SIMILARITY_THRESHOLD)
        return gate_result("ENTERED", "Face matched and entry was recorded.", participant=best["full_name"],
                           event=program["event_name"], program=program["program_name"], method="FACE",
                           similarity=best["similarity"], threshold=SIMILARITY_THRESHOLD)


@app.route("/convener/events/<int:event_id>/programs/new", methods=["GET", "POST"])
@login_required
def create_program(event_id):
    user = current_user()
    with get_db() as db:
        event = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        if event is None or not can_manage_event_programs(db, event_id, user["id"]):
            abort(404)
        if request.method == "POST":
            values, error = parse_program_form(request.form)
            host_email = request.form.get("host_email", "").strip().lower()
            co_host_email = request.form.get("co_host_email", "").strip().lower()
            host = db.execute("SELECT id FROM users WHERE email=?", (host_email,)).fetchone() if host_email else None
            co_host = db.execute("SELECT id FROM users WHERE email=?", (co_host_email,)).fetchone() if co_host_email else None
            if error:
                flash(error, "error")
            elif host is None:
                flash("Assign a Program Host using an existing registered user's email.", "error")
            elif co_host_email and co_host is None:
                flash("The Co-Host must be an existing registered user.", "error")
            elif co_host is not None and co_host["id"] == host["id"]:
                flash("Program Host and Co-Host must be different users.", "error")
            else:
                cursor = db.execute(
                    """INSERT INTO programs(event_id,program_name,description,category,participation_mode,team_size,
                       start_at,end_at,registration_deadline,venue,fee,status)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,'UPCOMING')""",
                    (event_id, values["program_name"], values["description"], values["category"],
                     values["participation_mode"], values["team_size"], values["start_at"], values["end_at"],
                     values["registration_deadline"], values["venue"], values["fee"]),
                )
                program_id = cursor.lastrowid
                db.execute("INSERT INTO program_hosts(program_id,user_id,role) VALUES(?,?,'HOST')", (program_id, host["id"]))
                if co_host:
                    db.execute("INSERT INTO program_hosts(program_id,user_id,role) VALUES(?,?,'CO_HOST')", (program_id, co_host["id"]))
                created = db.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone()
                refresh_program_status(db, created)
                flash("Program created and Program Host assigned.", "success")
                return redirect(url_for("convener_event_dashboard", event_id=event_id))
    return render_template("program_form.html", event=event, program=None, is_event_manager=True)


@app.route("/programs/<int:program_id>/edit", methods=["GET", "POST"])
@login_required
def edit_program(program_id):
    user = current_user()
    with get_db() as db:
        program = get_program_access(db, program_id, user["id"])
        if program is None or not can_manage_program(program, user["id"]):
            abort(404)
        is_event_manager = program["primary_convener_id"] == user["id"] or bool(program["is_event_convener"])
        if request.method == "POST":
            values, error = parse_program_form(request.form)
            if error:
                flash(error, "error")
            else:
                result = db.execute(
                    """UPDATE programs SET program_name=?,description=?,category=?,participation_mode=?,team_size=?,
                       start_at=?,end_at=?,registration_deadline=?,venue=?,fee=?,updated_at=CURRENT_TIMESTAMP
                       WHERE id=? AND (event_id IN (SELECT id FROM events WHERE primary_convener_id=? OR id IN
                         (SELECT event_id FROM event_co_conveners WHERE user_id=?)) OR id IN
                         (SELECT program_id FROM program_hosts WHERE user_id=?))""",
                    (values["program_name"], values["description"], values["category"], values["participation_mode"],
                     values["team_size"], values["start_at"], values["end_at"], values["registration_deadline"],
                     values["venue"], values["fee"], program_id, user["id"], user["id"], user["id"]),
                )
                if not result.rowcount:
                    abort(404)
                updated = db.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone()
                refresh_program_status(db, updated)
                flash("Program updated.", "success")
                return redirect(url_for("program_detail", program_id=program_id))
        program = dict(program, status=refresh_program_status(db, program))
    return render_template("program_form.html", event={"id": program["event_id"], "event_name": program["event_name"]},
                           program=program, is_event_manager=is_event_manager)


@app.route("/programs/<int:program_id>")
@login_required
def program_detail(program_id):
    user = current_user()
    with get_db() as db:
        program = get_program_access(db, program_id, user["id"])
        if program is None:
            abort(404)
        is_event_manager = program["primary_convener_id"] == user["id"] or bool(program["is_event_convener"])
        is_program_host = bool(program["is_program_host"])
        registration = db.execute("SELECT * FROM participant_registrations WHERE program_id=? AND user_id=?", (program_id, user["id"])).fetchone()
        if not (is_event_manager or is_program_host or program["event_visibility"] == "PUBLIC" or registration is not None):
            abort(404)
        program = dict(program, status=refresh_program_status(db, program))
        hosts = db.execute(
            "SELECT ph.role,u.id AS user_id,u.full_name,u.email FROM program_hosts ph "
            "JOIN users u ON u.id=ph.user_id WHERE ph.program_id=? "
            "ORDER BY CASE ph.role WHEN 'HOST' THEN 0 ELSE 1 END",
            (program_id,),
        ).fetchall()
        registration_open = (program["event_visibility"] == "PUBLIC" and program["status"] != "CANCELLED"
                             and datetime.now() <= datetime.fromisoformat(program["registration_deadline"]))
        participant_team_count = 0
        if registration is not None and program["participation_mode"] == "TEAM":
            participant_team_count = db.execute(
                "SELECT COUNT(*) FROM participant_teams WHERE program_id=? AND status='ACTIVE'", (program_id,)
            ).fetchone()[0]
    return render_template("program_detail.html", program=program, hosts=hosts, is_event_manager=is_event_manager,
                           is_program_host=is_program_host,
                           can_manage=can_manage_program(program, user["id"]), registration=registration,
                           registration_open=registration_open, participant_team_count=participant_team_count)


def participant_program_registration(db, program_id, user_id):
    program = db.execute(
        """SELECT p.*,e.event_name,e.visibility AS event_visibility
           FROM programs p JOIN events e ON e.id=p.event_id WHERE p.id=?""",
        (program_id,),
    ).fetchone()
    if program is None or program["participation_mode"] != "TEAM":
        return None, None
    registration = db.execute(
        """SELECT * FROM participant_registrations
           WHERE program_id=? AND event_id=? AND user_id=? AND registration_mode='TEAM'""",
        (program_id, program["event_id"], user_id),
    ).fetchone()
    return program, registration


def participant_team_open(db, program):
    status = refresh_program_status(db, program)
    return status != "CANCELLED" and datetime.now() <= datetime.fromisoformat(program["registration_deadline"])


def get_participant_team_access(db, team_id, user_id):
    team = db.execute(
        """SELECT t.*,p.program_name,p.participation_mode,p.team_size,p.registration_deadline,p.status AS program_status,
                  e.event_name,cap.full_name AS captain_name,pr.id AS viewer_registration_id,
                  CASE WHEN t.captain_registration_id=pr.id THEN 1 ELSE 0 END AS is_captain,
                  EXISTS(SELECT 1 FROM participant_team_members m
                         WHERE m.team_id=t.id AND m.registration_id=pr.id) AS is_member
           FROM participant_teams t JOIN programs p ON p.id=t.program_id AND p.event_id=t.event_id
           JOIN events e ON e.id=t.event_id
           JOIN participant_registrations cap ON cap.id=t.captain_registration_id
           JOIN participant_registrations pr ON pr.program_id=t.program_id AND pr.event_id=t.event_id AND pr.user_id=?
           WHERE t.id=? AND t.status='ACTIVE' AND p.participation_mode='TEAM' AND pr.registration_mode='TEAM'""",
        (user_id, team_id),
    ).fetchone()
    return team


def participant_team_members(db, team_id):
    return db.execute(
        """SELECT m.registration_id,m.joined_at,pr.full_name,pr.email,
                  CASE WHEN m.registration_id=t.captain_registration_id THEN 1 ELSE 0 END AS is_captain
           FROM participant_team_members m JOIN participant_registrations pr
             ON pr.id=m.registration_id AND pr.program_id=m.program_id AND pr.event_id=m.event_id
           JOIN participant_teams t ON t.id=m.team_id
           WHERE m.team_id=? ORDER BY m.joined_at,m.registration_id""",
        (team_id,),
    ).fetchall()


@app.route("/programs/<int:program_id>/participant-teams")
@login_required
def participant_program_teams(program_id):
    user = current_user()
    with get_db() as db:
        program, registration = participant_program_registration(db, program_id, user["id"])
        if program is None or registration is None:
            abort(404)
        formation_open = participant_team_open(db, program)
        teams = db.execute(
            """SELECT t.*,pr.full_name AS captain_name,
                      (SELECT COUNT(*) FROM participant_team_members m WHERE m.team_id=t.id) AS member_count,
                      (SELECT 1 FROM participant_team_members m WHERE m.team_id=t.id AND m.registration_id=?) AS viewer_is_member,
                      (t.captain_registration_id=?) AS viewer_is_captain
               FROM participant_teams t JOIN participant_registrations pr ON pr.id=t.captain_registration_id
               WHERE t.program_id=? AND t.event_id=? AND t.status='ACTIVE' ORDER BY t.created_at,t.id""",
            (registration["id"], registration["id"], program_id, program["event_id"]),
        ).fetchall()
        my_team = db.execute(
            "SELECT team_id FROM participant_team_members WHERE program_id=? AND registration_id=?",
            (program_id, registration["id"]),
        ).fetchone()
        can_create = formation_open and my_team is None
        team_details = [(team, participant_team_members(db, team["id"])) for team in teams]
    return render_template("participant_teams.html", program=program, registration=registration,
                           teams=team_details, my_team_id=my_team["team_id"] if my_team else None,
                           formation_open=formation_open, can_create=can_create)


@app.route("/programs/<int:program_id>/participant-teams/create", methods=["POST"])
@login_required
def create_participant_team(program_id):
    user = current_user()
    with get_db() as db:
        program, registration = participant_program_registration(db, program_id, user["id"])
        if program is None or registration is None:
            abort(404)
        if not participant_team_open(db, program):
            flash("Team formation is closed for this program.", "error")
        elif db.execute("SELECT 1 FROM participant_team_members WHERE program_id=? AND registration_id=?",
                        (program_id, registration["id"])).fetchone():
            flash("You already belong to a team for this program.", "error")
        else:
            try:
                cursor = db.execute(
                    "INSERT INTO participant_teams(program_id,event_id,creator_registration_id,captain_registration_id) VALUES(?,?,?,?)",
                    (program_id, program["event_id"], registration["id"], registration["id"]),
                )
                db.execute(
                    "INSERT INTO participant_team_members(team_id,program_id,event_id,registration_id) VALUES(?,?,?,?)",
                    (cursor.lastrowid, program_id, program["event_id"], registration["id"]),
                )
                flash("Your participant team was created. You are its captain.", "success")
            except sqlite3.IntegrityError:
                flash("You already belong to or captain a team for this program.", "error")
    return redirect(url_for("participant_program_teams", program_id=program_id))


@app.route("/participant-teams/<int:team_id>/members", methods=["POST"])
@login_required
def add_participant_team_member(team_id):
    user = current_user()
    email = request.form.get("email", "").strip().lower()
    with get_db() as db:
        team = get_participant_team_access(db, team_id, user["id"])
        if team is None:
            abort(404)
        if not team["is_captain"]:
            abort(403)
        program = db.execute("SELECT * FROM programs WHERE id=?", (team["program_id"],)).fetchone()
        if not participant_team_open(db, program):
            flash("No new members can be added after the deadline or cancellation.", "error")
        elif db.execute("SELECT COUNT(*) FROM participant_team_members WHERE team_id=?", (team_id,)).fetchone()[0] >= team["team_size"]:
            flash("This team has reached the configured maximum size.", "error")
        else:
            candidate = db.execute(
                """SELECT pr.id,pr.full_name FROM users u JOIN participant_registrations pr ON pr.user_id=u.id
                   WHERE lower(u.email)=? AND pr.program_id=? AND pr.event_id=? AND pr.registration_mode='TEAM'""",
                (email, team["program_id"], team["event_id"]),
            ).fetchone() if email else None
            if candidate is None:
                flash("That user must be registered for this team program first.", "error")
            elif candidate["id"] == team["captain_registration_id"]:
                flash("You are already the captain of this team.", "error")
            elif db.execute("SELECT 1 FROM participant_team_members WHERE program_id=? AND registration_id=?",
                            (team["program_id"], candidate["id"])).fetchone():
                flash("That participant already belongs to a team for this program.", "error")
            else:
                try:
                    db.execute(
                        "INSERT INTO participant_team_members(team_id,program_id,event_id,registration_id) VALUES(?,?,?,?)",
                        (team_id, team["program_id"], team["event_id"], candidate["id"]),
                    )
                    flash(f"{candidate['full_name']} was added to your team.", "success")
                except sqlite3.IntegrityError:
                    flash("That participant already belongs to a team for this program.", "error")
    return redirect(url_for("participant_team_detail", team_id=team_id))


@app.route("/participant-teams/<int:team_id>")
@login_required
def participant_team_detail(team_id):
    user = current_user()
    with get_db() as db:
        team = get_participant_team_access(db, team_id, user["id"])
        if team is None:
            abort(404)
        program = db.execute("SELECT * FROM programs WHERE id=?", (team["program_id"],)).fetchone()
        formation_open = participant_team_open(db, program)
        members = participant_team_members(db, team_id)
        member_count = len(members)
    return render_template("participant_team_detail.html", team=team, members=members,
                           formation_open=formation_open, at_capacity=member_count >= team["team_size"])


@app.route("/participant-teams/<int:team_id>/members/<int:registration_id>/remove", methods=["POST"])
@login_required
def remove_participant_team_member(team_id, registration_id):
    user = current_user()
    with get_db() as db:
        team = get_participant_team_access(db, team_id, user["id"])
        if team is None:
            abort(404)
        if not team["is_captain"]:
            abort(403)
        if registration_id == team["captain_registration_id"]:
            abort(403)
        result = db.execute(
            "DELETE FROM participant_team_members WHERE team_id=? AND registration_id=?",
            (team_id, registration_id),
        )
        flash("Participant removed from the team." if result.rowcount else "That participant is not in this team.",
              "success" if result.rowcount else "error")
    return redirect(url_for("participant_team_detail", team_id=team_id))


@app.route("/participant-teams/<int:team_id>/leave", methods=["POST"])
@login_required
def leave_participant_team(team_id):
    user = current_user()
    with get_db() as db:
        team = get_participant_team_access(db, team_id, user["id"])
        if team is None:
            abort(404)
        member = db.execute(
            "SELECT 1 FROM participant_team_members WHERE team_id=? AND registration_id=?",
            (team_id, team["viewer_registration_id"]),
        ).fetchone()
        if member is None:
            abort(403)
        if team["is_captain"]:
            successor = db.execute(
                """SELECT registration_id FROM participant_team_members
                   WHERE team_id=? AND registration_id<>? ORDER BY joined_at,registration_id LIMIT 1""",
                (team_id, team["viewer_registration_id"]),
            ).fetchone()
            if successor:
                db.execute("UPDATE participant_teams SET captain_registration_id=? WHERE id=?",
                           (successor["registration_id"], team_id))
                db.execute("DELETE FROM participant_team_members WHERE team_id=? AND registration_id=?",
                           (team_id, team["viewer_registration_id"]))
                flash("You left the team and captaincy transferred to its earliest member.", "success")
            else:
                db.execute("DELETE FROM participant_team_members WHERE team_id=? AND registration_id=?",
                           (team_id, team["viewer_registration_id"]))
                db.execute("UPDATE participant_teams SET status='DISBANDED',disbanded_at=CURRENT_TIMESTAMP WHERE id=?",
                           (team_id,))
                flash("You left the team. It is now disbanded because it had no other members.", "success")
        else:
            db.execute("DELETE FROM participant_team_members WHERE team_id=? AND registration_id=?",
                       (team_id, team["viewer_registration_id"]))
            flash("You left the participant team.", "success")
    return redirect(url_for("participant_program_teams", program_id=team["program_id"]))


def participant_type_values(form):
    participant_type = form.get("participant_type", "").strip().upper()
    if participant_type not in {"UNIVERSITY", "OUTSIDER"}:
        return None, None, "Choose University or Outsider participant type."
    institute_id = form.get("institute_id", "").strip()
    if participant_type == "UNIVERSITY" and not institute_id:
        return None, None, "Institute/university ID is required for University participants."
    if institute_id and len(institute_id) > 150:
        return None, None, "Institute/university ID must be 150 characters or fewer."
    return participant_type, institute_id if participant_type == "UNIVERSITY" else None, None


def registration_window_open(db, program):
    status = refresh_program_status(db, program)
    return program["event_visibility"] == "PUBLIC" and status != "CANCELLED" and datetime.now() <= datetime.fromisoformat(program["registration_deadline"])


@app.route("/programs/<int:program_id>/register", methods=["GET", "POST"])
@login_required
def register_for_program(program_id):
    user = current_user()
    if not user["profile_completed"]:
        flash("Complete your profile before registering for a program.", "error")
        return redirect(url_for("profile"))
    with get_db() as db:
        program = get_program_access(db, program_id, user["id"])
        if program is None or program["event_visibility"] != "PUBLIC":
            abort(404)
        if request.method == "POST":
            if program["status"] == "CANCELLED":
                flash("Registration is closed because this program was cancelled.", "error")
                return redirect(url_for("program_detail", program_id=program_id))
            if datetime.now() > datetime.fromisoformat(program["registration_deadline"]):
                flash("The registration deadline has passed.", "error")
                return redirect(url_for("program_detail", program_id=program_id))
            if db.execute("SELECT 1 FROM participant_registrations WHERE program_id=? AND user_id=?", (program_id, user["id"])).fetchone():
                flash("You are already registered for this program.", "error")
                return redirect(url_for("program_detail", program_id=program_id))
            participant_type, institute_id, error = participant_type_values(request.form)
            accommodation_required = 1 if request.form.get("accommodation_required") == "1" else 0
            if error:
                flash(error, "error")
            else:
                try:
                    cursor = db.execute(
                        """INSERT INTO participant_registrations
                           (event_id,program_id,user_id,participant_type,institute_id,full_name,email,phone,institution,registration_mode,accommodation_required)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                        (program["event_id"], program_id, user["id"], participant_type, institute_id,
                         user["full_name"], user["email"], user["phone"] or "", user["institution"] or "",
                         program["participation_mode"], accommodation_required),
                    )
                    flash("Registration completed.", "success")
                    if Decimal(str(program["fee"] or 0)) > 0:
                        return redirect(url_for("participant_payment", registration_id=cursor.lastrowid))
                    return redirect(url_for("participant_registration_detail", registration_id=cursor.lastrowid))
                except sqlite3.IntegrityError:
                    flash("You are already registered for this program.", "error")
                    return redirect(url_for("program_detail", program_id=program_id))
        else:
            if not registration_window_open(db, program):
                flash("This program is not currently accepting registrations.", "error")
                return redirect(url_for("program_detail", program_id=program_id))
            if db.execute("SELECT 1 FROM participant_registrations WHERE program_id=? AND user_id=?", (program_id, user["id"])).fetchone():
                flash("You are already registered for this program.", "error")
                return redirect(url_for("program_detail", program_id=program_id))
    return render_template("participant_registration_form.html", program=program, user=user, registration=None)


def get_owned_registration(db, registration_id, user_id):
    return db.execute(
        """SELECT pr.*,p.program_name,p.status AS program_status,p.participation_mode,p.registration_deadline,p.event_id,
                  e.event_name,e.visibility AS event_visibility
           FROM participant_registrations pr JOIN programs p ON p.id=pr.program_id AND p.event_id=pr.event_id
           JOIN events e ON e.id=pr.event_id WHERE pr.id=? AND pr.user_id=?""",
        (registration_id, user_id),
    ).fetchone()


def registration_can_edit(db, registration):
    program = db.execute("SELECT * FROM programs WHERE id=?", (registration["program_id"],)).fetchone()
    if program is None or refresh_program_status(db, program) == "CANCELLED":
        return False
    return datetime.now() <= datetime.fromisoformat(registration["registration_deadline"])


@app.route("/participant-registrations/<int:registration_id>")
@login_required
def participant_registration_detail(registration_id):
    user = current_user()
    with get_db() as db:
        registration = get_owned_registration(db, registration_id, user["id"])
        if registration is None:
            abort(404)
        can_edit = registration_can_edit(db, registration)
        program = db.execute("SELECT fee,status FROM programs WHERE id=?", (registration["program_id"],)).fetchone()
        latest_payment = db.execute(
            "SELECT id,status,amount_cents,receipt_number,created_at,processed_at FROM payment_records WHERE registration_id=? ORDER BY id DESC LIMIT 1",
            (registration_id,),
        ).fetchone()
        successful_payment = db.execute(
            "SELECT id,status,amount_cents,receipt_number,created_at,processed_at FROM payment_records WHERE registration_id=? AND status='SUCCESS' ORDER BY id DESC LIMIT 1",
            (registration_id,),
        ).fetchone()
        active_qr_pass = db.execute(
            "SELECT id,pass_number,status,created_at FROM qr_passes WHERE registration_id=? AND status='ACTIVE'",
            (registration_id,),
        ).fetchone()
    return render_template("participant_registration_detail.html", registration=registration, can_edit=can_edit,
                           fee=program["fee"], program_status=program["status"], latest_payment=latest_payment,
                           successful_payment=successful_payment, active_qr_pass=active_qr_pass)


@app.route("/participant-registrations/<int:registration_id>/edit", methods=["GET", "POST"])
@login_required
def edit_participant_registration(registration_id):
    user = current_user()
    with get_db() as db:
        registration = get_owned_registration(db, registration_id, user["id"])
        if registration is None:
            abort(404)
        if not registration_can_edit(db, registration):
            if request.method == "POST":
                flash("This registration can no longer be changed.", "error")
                return redirect(url_for("participant_registration_detail", registration_id=registration_id))
            flash("The deadline has passed or the program was cancelled. Registration is view-only.", "error")
            return redirect(url_for("participant_registration_detail", registration_id=registration_id))
        if request.method == "POST":
            participant_type, institute_id, error = participant_type_values(request.form)
            accommodation_required = 1 if request.form.get("accommodation_required") == "1" else 0
            if error:
                flash(error, "error")
            else:
                db.execute(
                    """UPDATE participant_registrations SET participant_type=?,institute_id=?,accommodation_required=?,full_name=?,email=?,phone=?,institution=?,updated_at=CURRENT_TIMESTAMP
                       WHERE id=? AND user_id=?""",
                    (participant_type, institute_id, accommodation_required, user["full_name"], user["email"], user["phone"] or "",
                     user["institution"] or "", registration_id, user["id"]),
                )
                flash("Registration details updated.", "success")
                return redirect(url_for("participant_registration_detail", registration_id=registration_id))
    return render_template("participant_registration_form.html", program=registration, user=user, registration=registration)


def get_owned_payment(db, payment_id, user_id):
    return db.execute(
        """SELECT pay.*,pr.user_id,pr.full_name,pr.program_id,pr.event_id,
                  p.program_name,p.status AS program_status,p.fee,e.event_name
           FROM payment_records pay
           JOIN participant_registrations pr ON pr.id=pay.registration_id
           JOIN programs p ON p.id=pr.program_id AND p.event_id=pr.event_id
           JOIN events e ON e.id=pr.event_id
           WHERE pay.id=? AND pr.user_id=?""",
        (payment_id, user_id),
    ).fetchone()


def fee_in_cents(fee):
    return int((Decimal(str(fee or 0)) * 100).quantize(Decimal("1")))


def mock_receipt_number():
    return "MOCK-" + secrets.token_hex(8).upper()


@app.route("/participant-registrations/<int:registration_id>/payment", methods=["GET"])
@login_required
def participant_payment(registration_id):
    user = current_user()
    with get_db() as db:
        registration = get_owned_registration(db, registration_id, user["id"])
        if registration is None:
            abort(404)
        program = db.execute("SELECT * FROM programs WHERE id=?", (registration["program_id"],)).fetchone()
        amount_cents = fee_in_cents(program["fee"])
        if amount_cents <= 0:
            flash("This program is free; no payment is required.", "success")
            return redirect(url_for("participant_registration_detail", registration_id=registration_id))
        if refresh_program_status(db, program) == "CANCELLED":
            db.execute("UPDATE payment_records SET status='FAILED',processed_at=CURRENT_TIMESTAMP WHERE registration_id=? AND status='PENDING'",
                       (registration_id,))
            flash("Payment is unavailable because this program was cancelled.", "error")
            return redirect(url_for("participant_registration_detail", registration_id=registration_id))
        success = db.execute(
            "SELECT id FROM payment_records WHERE registration_id=? AND status='SUCCESS' ORDER BY id DESC LIMIT 1",
            (registration_id,),
        ).fetchone()
        if success:
            return redirect(url_for("payment_receipt", payment_id=success["id"]))
        payment = db.execute(
            "SELECT * FROM payment_records WHERE registration_id=? AND status='PENDING' ORDER BY id DESC LIMIT 1",
            (registration_id,),
        ).fetchone()
        if payment is None:
            payment_id = db.execute(
                "INSERT INTO payment_records(registration_id,amount_cents,status) VALUES(?,?,'PENDING')",
                (registration_id, amount_cents),
            ).lastrowid
            payment = db.execute("SELECT * FROM payment_records WHERE id=?", (payment_id,)).fetchone()
        elif payment["amount_cents"] != amount_cents:
            db.execute("UPDATE payment_records SET amount_cents=? WHERE id=? AND status='PENDING'",
                       (amount_cents, payment["id"]))
            payment = db.execute("SELECT * FROM payment_records WHERE id=?", (payment["id"],)).fetchone()
        context = dict(payment)
        context.update(event_name=registration["event_name"], program_name=registration["program_name"],
                       participant_name=registration["full_name"], amount=amount_cents / 100)
    return render_template("mock_payment.html", payment=context)


@app.route("/payments/<int:payment_id>/simulate", methods=["POST"])
@login_required
def simulate_payment(payment_id):
    user = current_user()
    outcome = request.form.get("outcome", "").strip().upper()
    with get_db() as db:
        payment = get_owned_payment(db, payment_id, user["id"])
        if payment is None:
            abort(404)
        if payment["status"] == "SUCCESS":
            return redirect(url_for("payment_receipt", payment_id=payment_id))
        if payment["status"] != "PENDING":
            flash("This payment attempt has already been processed. Start a new attempt if needed.", "error")
            return redirect(url_for("participant_payment", registration_id=payment["registration_id"]))
        program = db.execute("SELECT * FROM programs WHERE id=?", (payment["program_id"],)).fetchone()
        if fee_in_cents(program["fee"]) <= 0:
            db.execute("UPDATE payment_records SET status='FAILED',processed_at=CURRENT_TIMESTAMP WHERE id=? AND status='PENDING'", (payment_id,))
            flash("This program is free; no payment is required.", "success")
            return redirect(url_for("participant_registration_detail", registration_id=payment["registration_id"]))
        if refresh_program_status(db, program) == "CANCELLED":
            db.execute("UPDATE payment_records SET status='FAILED',processed_at=CURRENT_TIMESTAMP WHERE id=? AND status='PENDING'", (payment_id,))
            flash("Payment is unavailable because this program was cancelled.", "error")
            return redirect(url_for("participant_registration_detail", registration_id=payment["registration_id"]))
        if outcome not in {"SUCCESS", "FAILED"}:
            flash("Choose a mock payment outcome.", "error")
            return redirect(url_for("participant_payment", registration_id=payment["registration_id"]))
        if outcome == "FAILED":
            db.execute("UPDATE payment_records SET status='FAILED',processed_at=CURRENT_TIMESTAMP WHERE id=? AND status='PENDING'",
                       (payment_id,))
            flash("Mock payment marked as failed. No real transaction occurred.", "error")
            return redirect(url_for("payment_receipt", payment_id=payment_id))
        try:
            db.execute(
                "UPDATE payment_records SET amount_cents=?,status='SUCCESS',receipt_number=?,processed_at=CURRENT_TIMESTAMP WHERE id=? AND status='PENDING'",
                (fee_in_cents(program["fee"]), mock_receipt_number(), payment_id),
            )
        except sqlite3.IntegrityError:
            success = db.execute("SELECT id FROM payment_records WHERE registration_id=? AND status='SUCCESS'",
                                 (payment["registration_id"],)).fetchone()
            if success:
                return redirect(url_for("payment_receipt", payment_id=success["id"]))
            raise
        flash("Mock payment successful. No real transaction occurred.", "success")
    return redirect(url_for("payment_receipt", payment_id=payment_id))


@app.route("/payments/<int:payment_id>/receipt")
@login_required
def payment_receipt(payment_id):
    user = current_user()
    with get_db() as db:
        payment = get_owned_payment(db, payment_id, user["id"])
        if payment is None:
            abort(404)
    return render_template("payment_receipt.html", payment=payment)


def qr_pass_block_reason(db, registration, program):
    if refresh_program_status(db, program) == "CANCELLED":
        return "This cancelled program cannot receive new QR passes."
    if fee_in_cents(program["fee"]) > 0 and not db.execute(
        "SELECT 1 FROM payment_records WHERE registration_id=? AND status='SUCCESS' LIMIT 1",
        (registration["id"],),
    ).fetchone():
        return "A successful mock payment is required before generating this QR pass."
    return None


def make_qr_png(token):
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(token)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


@app.route("/participant-registrations/<int:registration_id>/qr-pass")
@login_required
def participant_qr_pass(registration_id):
    user = current_user()
    with get_db() as db:
        registration = get_owned_registration(db, registration_id, user["id"])
        if registration is None:
            abort(404)
        program = db.execute("SELECT * FROM programs WHERE id=?", (registration["program_id"],)).fetchone()
        pass_record = db.execute(
            "SELECT * FROM qr_passes WHERE registration_id=? AND status='ACTIVE'",
            (registration_id,),
        ).fetchone()
        if pass_record is None:
            reason = qr_pass_block_reason(db, registration, program)
            if reason:
                flash(reason, "error")
                return redirect(url_for("participant_registration_detail", registration_id=registration_id))
            revoked_pass = db.execute(
                "SELECT pass_number FROM qr_passes WHERE registration_id=? AND status='REVOKED' ORDER BY id DESC LIMIT 1",
                (registration_id,),
            ).fetchone()
            return render_template("qr_pass.html", registration=registration, qr_pass=None,
                                   revoked_pass=revoked_pass, pass_png=None, pass_status="NOT GENERATED")
        program_status = refresh_program_status(db, program)
        pass_status = "ACTIVE" if program_status != "CANCELLED" else "INVALID · PROGRAM CANCELLED"
        pass_png = base64.b64encode(pass_record["qr_image"]).decode("ascii")
        pass_view = dict(pass_record)
    return render_template("qr_pass.html", registration=registration, qr_pass=pass_view,
                           revoked_pass=None, pass_png=pass_png, pass_status=pass_status)


@app.route("/participant-registrations/<int:registration_id>/qr-pass/create", methods=["POST"])
@login_required
def create_participant_qr_pass(registration_id):
    user = current_user()
    with get_db() as db:
        registration = get_owned_registration(db, registration_id, user["id"])
        if registration is None:
            abort(404)
        program = db.execute("SELECT * FROM programs WHERE id=?", (registration["program_id"],)).fetchone()
        reason = qr_pass_block_reason(db, registration, program)
        if reason:
            flash(reason, "error")
            return redirect(url_for("participant_registration_detail", registration_id=registration_id))
        active = db.execute(
            "SELECT id FROM qr_passes WHERE registration_id=? AND status='ACTIVE'",
            (registration_id,),
        ).fetchone()
        if active:
            return redirect(url_for("participant_qr_pass", registration_id=registration_id))
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        pass_number = "PASS-" + secrets.token_hex(8).upper()
        while db.execute("SELECT 1 FROM qr_passes WHERE pass_number=?", (pass_number,)).fetchone():
            pass_number = "PASS-" + secrets.token_hex(8).upper()
        qr_image = make_qr_png(token)
        try:
            db.execute(
                """INSERT INTO qr_passes(registration_id,event_id,program_id,token_hash,pass_number,qr_image)
                   VALUES(?,?,?,?,?,?)""",
                (registration_id, registration["event_id"], registration["program_id"], token_hash, pass_number, qr_image),
            )
        except sqlite3.IntegrityError:
            active = db.execute(
                "SELECT id FROM qr_passes WHERE registration_id=? AND status='ACTIVE'",
                (registration_id,),
            ).fetchone()
            if active:
                return redirect(url_for("participant_qr_pass", registration_id=registration_id))
            raise
        flash("Your QR pass has been generated.", "success")
    return redirect(url_for("participant_qr_pass", registration_id=registration_id))


@app.route("/qr-passes/<int:pass_id>/revoke", methods=["POST"])
@login_required
def revoke_participant_qr_pass(pass_id):
    user = current_user()
    with get_db() as db:
        pass_record = db.execute(
            """SELECT q.id,q.registration_id FROM qr_passes q
               JOIN participant_registrations pr ON pr.id=q.registration_id
               WHERE q.id=? AND pr.user_id=?""",
            (pass_id, user["id"]),
        ).fetchone()
        if pass_record is None:
            abort(404)
        result = db.execute(
            "UPDATE qr_passes SET status='REVOKED',revoked_at=CURRENT_TIMESTAMP WHERE id=? AND status='ACTIVE'",
            (pass_id,),
        )
        flash("QR pass revoked." if result.rowcount else "This QR pass is already revoked.",
              "success" if result.rowcount else "error")
    return redirect(url_for("participant_qr_pass", registration_id=pass_record["registration_id"]))


def qr_validation_result(valid, message, **details):
    return jsonify(valid=valid, status="VALID" if valid else "INVALID", message=message, **details)


@app.route("/events/<int:event_id>/programs/<int:program_id>/qr/validate", methods=["POST"])
@login_required
def validate_qr_pass(event_id, program_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        payload = request.form
    token = str(payload.get("token", "")).strip()
    if not token or len(token) > 256:
        return qr_validation_result(False, "A valid pass token is required."), 400
    with get_db() as db:
        program = get_program_access(db, program_id, user["id"])
        if program is None or program["event_id"] != event_id:
            abort(404)
        if not can_manage_program(program, user["id"]):
            abort(403)
        pass_record = active_qr_pass(db, event_id, program_id, token)
        if pass_record is None:
            return qr_validation_result(False, "Pass is invalid for this event/program or has been revoked.")
        # Validation is read-only: no use/attendance state is written in this phase.
        return qr_validation_result(
            True, "Pass is valid.", participant=pass_record["full_name"], event=pass_record["event_name"],
            program=pass_record["program_name"], pass_number=pass_record["pass_number"], used=False,
        )


@app.route("/programs/<int:program_id>/cancel", methods=["POST"])
@login_required
def cancel_program(program_id):
    user = current_user()
    with get_db() as db:
        program = get_program_access(db, program_id, user["id"])
        if program is None or not can_manage_program(program, user["id"]):
            abort(404)
        if program["status"] == "CANCELLED":
            flash("This program is already cancelled.", "error")
        else:
            db.execute("UPDATE programs SET status='CANCELLED',updated_at=CURRENT_TIMESTAMP WHERE id=?", (program_id,))
            flash("Program cancelled. It remains recorded in this event.", "success")
    return redirect(url_for("program_detail", program_id=program_id))


@app.route("/programs/<int:program_id>/hosts", methods=["POST"])
@login_required
def manage_program_hosts(program_id):
    user = current_user()
    action = request.form.get("action", "")
    role = request.form.get("role", "").upper()
    if action not in {"assign", "remove"} or role not in {"HOST", "CO_HOST"}:
        abort(400)
    with get_db() as db:
        program = get_program_access(db, program_id, user["id"])
        if program is None:
            abort(404)
        if not (program["primary_convener_id"] == user["id"] or program["is_event_convener"]):
            abort(403)
        if action == "remove":
            result = db.execute("DELETE FROM program_hosts WHERE program_id=? AND role=?", (program_id, role))
            flash("Program Host assignment removed." if result.rowcount else "No assignment exists for that role.",
                  "success" if result.rowcount else "error")
        else:
            email = request.form.get("email", "").strip().lower()
            assignee = db.execute("SELECT id,full_name FROM users WHERE email=?", (email,)).fetchone() if email else None
            if assignee is None:
                flash("Choose an existing registered user.", "error")
            elif db.execute("SELECT 1 FROM program_hosts WHERE program_id=? AND role=?", (program_id, role)).fetchone():
                flash("That Program Host role is already assigned. Remove it before assigning another user.", "error")
            elif db.execute("SELECT 1 FROM program_hosts WHERE program_id=? AND user_id=?", (program_id, assignee["id"])).fetchone():
                flash("The same user cannot be assigned as both Host and Co-Host.", "error")
            else:
                try:
                    db.execute("INSERT INTO program_hosts(program_id,user_id,role) VALUES(?,?,?)", (program_id, assignee["id"], role))
                    role_label = "Program Host" if role == "HOST" else "Co-Host"
                    flash(f"{assignee['full_name']} assigned as {role_label}.", "success")
                except sqlite3.IntegrityError:
                    flash("That host assignment already exists.", "error")
    return redirect(url_for("program_detail", program_id=program_id))


@app.route("/convener/events/<int:event_id>/teams", methods=["POST"])
@login_required
def create_event_team(event_id):
    user = current_user()
    team_name = request.form.get("team_name", "").strip()
    description = request.form.get("description", "").strip()
    leader_email = request.form.get("team_leader_email", "").strip().lower()
    with get_db() as db:
        if get_managed_event(db, event_id, user["id"]) is None:
            abort(404)
        if not team_name:
            flash("Team name is required.", "error")
        else:
            leader = db.execute("SELECT id,full_name FROM users WHERE email=?", (leader_email,)).fetchone() if leader_email else None
            if leader is None:
                flash("Enter the email of an existing registered user to be Team Leader.", "error")
            elif db.execute("SELECT 1 FROM event_teams WHERE event_id=? AND team_name=? COLLATE NOCASE", (event_id, team_name)).fetchone():
                flash("A team with that name already exists for this event.", "error")
            elif db.execute("SELECT 1 FROM event_teams WHERE event_id=? AND team_leader_id=?", (event_id, leader["id"])).fetchone():
                flash("That user already leads a team for this event.", "error")
            else:
                try:
                    db.execute("INSERT INTO event_teams(event_id,team_name,description,team_leader_id) VALUES(?,?,?,?)",
                               (event_id, team_name, description, leader["id"]))
                    flash(f"Team {team_name} created with {leader['full_name']} as Team Leader.", "success")
                except sqlite3.IntegrityError:
                    flash("The team name or Team Leader is already assigned for this event.", "error")
    return redirect(url_for("convener_event_dashboard", event_id=event_id))


def get_team_access(db, team_id, user_id):
    return db.execute(
        """SELECT t.*,e.event_name,e.primary_convener_id,
                  EXISTS(SELECT 1 FROM event_co_conveners cc WHERE cc.event_id=e.id AND cc.user_id=?) AS is_event_convener,
                  EXISTS(SELECT 1 FROM event_team_members tm WHERE tm.team_id=t.id AND tm.user_id=?) AS is_member
           FROM event_teams t JOIN events e ON e.id=t.event_id WHERE t.id=?""",
        (user_id, user_id, team_id),
    ).fetchone()


def can_manage_team_members(team, user_id):
    return team["team_leader_id"] == user_id or team["primary_convener_id"] == user_id or bool(team["is_event_convener"])


@app.route("/teams/<int:team_id>")
@login_required
def team_detail(team_id):
    user = current_user()
    with get_db() as db:
        team = get_team_access(db, team_id, user["id"])
        if team is None:
            abort(404)
        is_leader = team["team_leader_id"] == user["id"]
        is_event_manager = team["primary_convener_id"] == user["id"] or bool(team["is_event_convener"])
        if not (is_leader or is_event_manager or team["is_member"]):
            abort(404)
        leader = db.execute("SELECT full_name,email FROM users WHERE id=?", (team["team_leader_id"],)).fetchone()
        members = db.execute("SELECT u.id,u.full_name,u.email,tm.joined_at FROM event_team_members tm JOIN users u ON u.id=tm.user_id WHERE tm.team_id=? ORDER BY u.full_name,u.id", (team_id,)).fetchall()
    return render_template("team_detail.html", team=team, leader=leader, members=members,
                           is_leader=is_leader, can_manage=can_manage_team_members(team, user["id"]))


@app.route("/teams/<int:team_id>/members", methods=["POST"])
@login_required
def add_team_member(team_id):
    user = current_user()
    email = request.form.get("email", "").strip().lower()
    with get_db() as db:
        team = get_team_access(db, team_id, user["id"])
        if team is None:
            abort(404)
        if not can_manage_team_members(team, user["id"]):
            abort(403)
        member = db.execute("SELECT id,full_name FROM users WHERE email=?", (email,)).fetchone() if email else None
        if member is None:
            flash("Enter the email address of an existing registered user.", "error")
        elif member["id"] == team["team_leader_id"]:
            flash("The Team Leader is already shown as the team leader.", "error")
        elif db.execute("SELECT 1 FROM event_team_members WHERE team_id=? AND user_id=?", (team_id, member["id"])).fetchone():
            flash("That user is already a member of this team.", "error")
        else:
            try:
                db.execute("INSERT INTO event_team_members(team_id,user_id) VALUES(?,?)", (team_id, member["id"]))
                flash(f"{member['full_name']} added to the team.", "success")
            except sqlite3.IntegrityError:
                flash("That user is already a member of this team.", "error")
    return redirect(url_for("team_detail", team_id=team_id))


@app.route("/teams/<int:team_id>/members/<int:member_id>/remove", methods=["POST"])
@login_required
def remove_team_member(team_id, member_id):
    user = current_user()
    with get_db() as db:
        team = get_team_access(db, team_id, user["id"])
        if team is None:
            abort(404)
        if not can_manage_team_members(team, user["id"]):
            abort(403)
        result = db.execute("DELETE FROM event_team_members WHERE team_id=? AND user_id=? AND user_id<>?",
                            (team_id, member_id, team["team_leader_id"]))
        flash("Team member removed." if result.rowcount else "That user is not a removable member of this team.",
              "success" if result.rowcount else "error")
    return redirect(url_for("team_detail", team_id=team_id))


@app.route("/teams/<int:team_id>/leave", methods=["POST"])
@login_required
def leave_team(team_id):
    user = current_user()
    with get_db() as db:
        team = db.execute("SELECT id FROM event_teams WHERE id=?", (team_id,)).fetchone()
        if team is None:
            abort(404)
        result = db.execute("DELETE FROM event_team_members WHERE team_id=? AND user_id=?", (team_id, user["id"]))
        flash("You left the team." if result.rowcount else "You are not a member of this team.",
              "success" if result.rowcount else "error")
    return redirect(url_for("dashboard"))


@app.route("/convener/events/<int:event_id>/co-conveners", methods=["POST"])
@login_required
def add_co_convener(event_id):
    user = current_user()
    email = request.form.get("email", "").strip().lower()
    with get_db() as db:
        event = primary_owned_event(db, event_id, user["id"])
        if event is None:
            abort(403)
        invitee = db.execute("SELECT id,full_name FROM users WHERE email=?", (email,)).fetchone() if email else None
        if not email:
            flash("Enter the registered user's email address.", "error")
        elif invitee is None:
            flash("No registered user was found with that email.", "error")
        elif invitee["id"] == user["id"]:
            flash("The Primary Convener cannot also be assigned as a Co-Convener.", "error")
        else:
            try:
                db.execute("INSERT INTO event_co_conveners(event_id,user_id) VALUES(?,?)", (event_id, invitee["id"]))
                flash(f"{invitee['full_name']} added as Co-Convener.", "success")
            except sqlite3.IntegrityError:
                flash("That user is already a Co-Convener for this event.", "error")
    return redirect(url_for("convener_event_dashboard", event_id=event_id))


@app.route("/convener/events/<int:event_id>/co-conveners/<int:co_user_id>/remove", methods=["POST"])
@login_required
def remove_co_convener(event_id, co_user_id):
    user = current_user()
    with get_db() as db:
        if primary_owned_event(db, event_id, user["id"]) is None:
            abort(403)
        result = db.execute("DELETE FROM event_co_conveners WHERE event_id=? AND user_id=?", (event_id, co_user_id))
        if result.rowcount:
            flash("Co-Convener removed.", "success")
        else:
            flash("That user is not assigned as a Co-Convener for this event.", "error")
    return redirect(url_for("convener_event_dashboard", event_id=event_id))


@app.route("/convener/events/<int:event_id>/delete", methods=["POST"])
@login_required
def delete_convener_event(event_id):
    user = current_user()
    with get_db() as db:
        result = db.execute("DELETE FROM events WHERE id=? AND primary_convener_id=?", (event_id, user["id"]))
    if not result.rowcount:
        abort(404)
    flash("Event deleted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/root/events")
@root_required
def root_events():
    with get_db() as db:
        rows = db.execute("""SELECT e.id,e.event_name,e.organization_university,e.event_type,e.start_date,e.end_date,e.venue,e.visibility,e.status,e.created_at,u.full_name AS primary_convener
                            FROM events e JOIN users u ON u.id=e.primary_convener_id ORDER BY e.created_at DESC""").fetchall()
        events = [dict(row, status=refresh_event_status(db, row)) for row in rows]
    return render_template("root_events.html", events=events)


def event_analytics_data(db, event):
    programs = db.execute(
        """SELECT p.id,p.event_id,p.program_name,p.participation_mode,p.team_size,p.registration_deadline,
                  p.start_at,p.end_at,p.status,
                  (SELECT COUNT(*) FROM participant_registrations pr WHERE pr.program_id=p.id AND pr.event_id=p.event_id) AS registration_count,
                  (SELECT COUNT(*) FROM participant_teams t WHERE t.program_id=p.id AND t.event_id=p.event_id AND t.status='ACTIVE') AS team_count
           FROM programs p WHERE p.event_id=? ORDER BY p.start_at,p.id""", (event["id"],)
    ).fetchall()
    programs = [dict(program, status=refresh_program_status(db, program)) for program in programs]
    program_status_counts = {name: sum(program["status"] == name for program in programs)
                             for name in ("UPCOMING", "ONGOING", "COMPLETED", "CANCELLED")}
    registrations = db.execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(CASE WHEN participant_type='UNIVERSITY' THEN 1 ELSE 0 END),0) AS university,
                  COALESCE(SUM(CASE WHEN participant_type='OUTSIDER' THEN 1 ELSE 0 END),0) AS outsider
           FROM participant_registrations WHERE event_id=?""", (event["id"],)
    ).fetchone()
    payments = db.execute(
        """SELECT COUNT(DISTINCT CASE WHEN p.fee>0 THEN pr.id END) AS paid_registrations,
                  COALESCE(SUM(CASE WHEN pay.status='SUCCESS' THEN 1 ELSE 0 END),0) AS successful_count,
                  COALESCE(SUM(CASE WHEN pay.status='FAILED' THEN 1 ELSE 0 END),0) AS failed_count,
                  COALESCE(SUM(CASE WHEN pay.status='PENDING' THEN 1 ELSE 0 END),0) AS pending_count,
                  COALESCE(SUM(CASE WHEN pay.status='SUCCESS' THEN pay.amount_cents ELSE 0 END),0) AS successful_amount_cents
           FROM participant_registrations pr JOIN programs p ON p.id=pr.program_id AND p.event_id=pr.event_id
           LEFT JOIN payment_records pay ON pay.registration_id=pr.id WHERE pr.event_id=?""", (event["id"],)
    ).fetchone()
    attendance = db.execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(CASE WHEN verification_method='FACE' THEN 1 ELSE 0 END),0) AS face,
                  COALESCE(SUM(CASE WHEN verification_method='QR' THEN 1 ELSE 0 END),0) AS qr
           FROM attendance_entries WHERE event_id=?""", (event["id"],)
    ).fetchone()
    accommodation = db.execute(
        """SELECT COUNT(DISTINCT CASE WHEN pr.accommodation_required=1 THEN pr.user_id END) AS registered,
                  COUNT(DISTINCT aa.participant_user_id) AS allocated
           FROM participant_registrations pr LEFT JOIN accommodation_allocations aa
             ON aa.event_id=pr.event_id AND aa.participant_user_id=pr.user_id
           WHERE pr.event_id=?""", (event["id"],)
    ).fetchone()
    meetings = db.execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(CASE WHEN program_id IS NULL THEN 1 ELSE 0 END),0) AS event_level,
                  COALESCE(SUM(CASE WHEN program_id IS NOT NULL THEN 1 ELSE 0 END),0) AS program_level
           FROM meetings WHERE event_id=?""", (event["id"],)
    ).fetchone()
    attendance_by_program = db.execute(
        """SELECT p.id AS program_id,p.program_name,COUNT(a.id) AS attendance_count
           FROM programs p LEFT JOIN attendance_entries a ON a.program_id=p.id AND a.event_id=p.event_id
           WHERE p.event_id=? GROUP BY p.id,p.program_name ORDER BY p.start_at,p.id""", (event["id"],)
    ).fetchall()
    return {
        "programs": programs, "program_status_counts": program_status_counts,
        "registrations": registrations, "payments": payments, "attendance": attendance,
        "accommodation": accommodation, "meetings": meetings,
        "attendance_by_program": attendance_by_program,
    }


def program_analytics_data(db, program):
    registrations = db.execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(CASE WHEN participant_type='UNIVERSITY' THEN 1 ELSE 0 END),0) AS university,
                  COALESCE(SUM(CASE WHEN participant_type='OUTSIDER' THEN 1 ELSE 0 END),0) AS outsider
           FROM participant_registrations WHERE event_id=? AND program_id=?""",
        (program["event_id"], program["id"]),
    ).fetchone()
    payments = db.execute(
        """SELECT COUNT(pay.id) AS successful_count,
                  COALESCE(SUM(pay.amount_cents),0) AS amount_cents
           FROM payment_records pay JOIN participant_registrations pr ON pr.id=pay.registration_id
           WHERE pr.event_id=? AND pr.program_id=? AND pay.status='SUCCESS'""",
        (program["event_id"], program["id"]),
    ).fetchone()
    attendance = db.execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(CASE WHEN verification_method='FACE' THEN 1 ELSE 0 END),0) AS face,
                  COALESCE(SUM(CASE WHEN verification_method='QR' THEN 1 ELSE 0 END),0) AS qr
           FROM attendance_entries WHERE event_id=? AND program_id=?""",
        (program["event_id"], program["id"]),
    ).fetchone()
    teams = db.execute(
        "SELECT COUNT(*) FROM participant_teams WHERE event_id=? AND program_id=? AND status='ACTIVE'",
        (program["event_id"], program["id"]),
    ).fetchone()[0] if program["participation_mode"] == "TEAM" else 0
    accommodation_count = db.execute(
        """SELECT COUNT(DISTINCT aa.id) FROM accommodation_allocations aa
           JOIN participant_registrations pr ON pr.event_id=aa.event_id AND pr.user_id=aa.participant_user_id
           WHERE pr.event_id=? AND pr.program_id=?""", (program["event_id"], program["id"])
    ).fetchone()[0]
    meeting_count = db.execute(
        "SELECT COUNT(*) FROM meetings WHERE event_id=? AND program_id=?",
        (program["event_id"], program["id"]),
    ).fetchone()[0]
    return {"registrations": registrations, "payments": payments, "attendance": attendance,
            "team_count": teams, "accommodation_count": accommodation_count,
            "meeting_count": meeting_count}


@app.route("/convener/events/<int:event_id>/analytics")
@login_required
def event_analytics(event_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    with get_db() as db:
        event = get_managed_event(db, event_id, user["id"])
        if event is None:
            abort(403)
        event = dict(event, status=refresh_event_status(db, event))
        analytics = event_analytics_data(db, event)
    return render_template("event_analytics.html", event=event, analytics=analytics)


@app.route("/programs/<int:program_id>/analytics")
@login_required
def program_analytics(program_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    with get_db() as db:
        program = db.execute("SELECT * FROM programs WHERE id=?", (program_id,)).fetchone()
        if program is None:
            abort(404)
        event = get_managed_event(db, program["event_id"], user["id"])
        if event is None:
            abort(403)
        program = dict(program, status=refresh_program_status(db, program), event_name=event["event_name"])
        analytics = program_analytics_data(db, program)
    return render_template("program_analytics.html", program=program, analytics=analytics)


@app.route("/root/analytics")
@root_required
def root_analytics():
    with get_db() as db:
        event_rows = db.execute("SELECT * FROM events ORDER BY created_at DESC,id").fetchall()
        events = []
        for row in event_rows:
            status = refresh_event_status(db, row)
            counts = db.execute(
                """SELECT (SELECT COUNT(*) FROM programs p WHERE p.event_id=e.id) AS program_count,
                          (SELECT COUNT(*) FROM participant_registrations pr WHERE pr.event_id=e.id) AS registration_count,
                          (SELECT COUNT(*) FROM attendance_entries a WHERE a.event_id=e.id) AS attendance_count
                   FROM events e WHERE e.id=?""", (row["id"],)
            ).fetchone()
            events.append({"id":row["id"],"event_name":row["event_name"],"status":status,
                           "program_count":counts["program_count"],"registration_count":counts["registration_count"],
                           "attendance_count":counts["attendance_count"]})
        event_totals = {name: sum(item["status"] == name for item in events)
                        for name in ("UPCOMING", "ONGOING", "COMPLETED")}
        totals = db.execute(
            """SELECT (SELECT COUNT(*) FROM events) AS event_count,
                      (SELECT COUNT(*) FROM programs) AS program_count,
                      (SELECT COUNT(*) FROM participant_registrations) AS registration_count,
                      (SELECT COUNT(*) FROM payment_records WHERE status='SUCCESS') AS successful_payment_count,
                      (SELECT COALESCE(SUM(amount_cents),0) FROM payment_records WHERE status='SUCCESS') AS successful_amount_cents,
                      (SELECT COUNT(*) FROM attendance_entries) AS attendance_count"""
        ).fetchone()
    return render_template("root_analytics.html", totals=totals, event_totals=event_totals, events=events)


@app.route("/event-requests/new", methods=["GET", "POST"])
@login_required
def new_event_request():
    user = current_user()
    if user["role"] == "root":
        return redirect(url_for("root_event_requests"))
    if request.method == "POST":
        event_title = request.form.get("event_title", "").strip()
        description = request.form.get("description", "").strip()
        proposed_date = request.form.get("proposed_date", "").strip()
        venue = request.form.get("venue", "").strip()
        if not all((event_title, description, proposed_date, venue)):
            flash("Complete all event request fields.", "error")
        else:
            try:
                parsed_date = date.fromisoformat(proposed_date)
            except ValueError:
                flash("Choose a valid proposed date.", "error")
            else:
                if parsed_date < date.today():
                    flash("The proposed event date must be today or later.", "error")
                else:
                    with get_db() as db:
                        db.execute(
                            "INSERT INTO event_requests (requester_id,event_title,description,proposed_date,venue) VALUES (?,?,?,?,?)",
                            (user["id"], event_title, description, proposed_date, venue),
                        )
                        created = db.execute("SELECT * FROM event_requests WHERE id = last_insert_rowid()").fetchone()
                        record_request_history(db, created, user["id"], "submitted")
                    flash("Event request submitted for root review.", "success")
                    return redirect(url_for("dashboard"))
    return render_template("event_request_new.html")


@app.route("/event-requests/<int:request_id>/edit", methods=["GET", "POST"])
@login_required
def edit_event_request(request_id):
    user = current_user()
    if user["role"] == "root":
        abort(403)
    with get_db() as db:
        item = db.execute(
            "SELECT * FROM event_requests WHERE id = ? AND requester_id = ?",
            (request_id, user["id"]),
        ).fetchone()
    if item is None:
        abort(404)
    if item["status"] != "rejected":
        flash("Only rejected requests can be edited and resubmitted.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        action = request.form.get("action", "")
        if action not in {"save", "resubmit"}:
            abort(400)
        event_title = request.form.get("event_title", "").strip()
        description = request.form.get("description", "").strip()
        proposed_date = request.form.get("proposed_date", "").strip()
        venue = request.form.get("venue", "").strip()
        if not all((event_title, description, proposed_date, venue)):
            flash("Complete all event request fields.", "error")
        else:
            try:
                parsed_date = date.fromisoformat(proposed_date)
            except ValueError:
                flash("Choose a valid proposed date.", "error")
            else:
                if parsed_date < date.today():
                    flash("The proposed event date must be today or later.", "error")
                else:
                    with get_db() as db:
                        # Preserve the pre-edit contents for older requests created before history was added.
                        has_history = db.execute(
                            "SELECT 1 FROM event_request_history WHERE event_request_id = ? LIMIT 1",
                            (request_id,),
                        ).fetchone()
                        if not has_history:
                            record_request_history(db, item, user["id"], "rejected")
                        new_status = "pending" if action == "resubmit" else "rejected"
                        result = db.execute(
                            """UPDATE event_requests
                               SET event_title = ?, description = ?, proposed_date = ?, venue = ?, status = ?
                               WHERE id = ? AND requester_id = ? AND status = 'rejected'""",
                            (event_title, description, proposed_date, venue, new_status, request_id, user["id"]),
                        )
                        if result.rowcount == 0:
                            flash("This request is no longer available to edit.", "error")
                            return redirect(url_for("dashboard"))
                        updated = db.execute("SELECT * FROM event_requests WHERE id = ?", (request_id,)).fetchone()
                        record_request_history(
                            db, updated, user["id"], "resubmitted" if action == "resubmit" else "edited"
                        )
                    if action == "resubmit":
                        flash("Updated request resubmitted to Root for review.", "success")
                        return redirect(url_for("dashboard"))
                    flash("Changes saved. Your request remains rejected until you resubmit it.", "success")
                    return redirect(url_for("edit_event_request", request_id=request_id))

    with get_db() as db:
        history = db.execute(
            "SELECT * FROM event_request_history WHERE event_request_id = ? ORDER BY id DESC",
            (request_id,),
        ).fetchall()
    return render_template("event_request_edit.html", item=item, history=history)


@app.route("/root/event-requests")
@root_required
def root_event_requests():
    with get_db() as db:
        event_requests = db.execute(
            """SELECT r.*, u.full_name AS requester_name, u.email AS requester_email,
                      u.institution AS requester_institution
               FROM event_requests r JOIN users u ON u.id = r.requester_id
               ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END,
                        r.requested_at ASC, r.id ASC"""
        ).fetchall()
        history_by_request = {}
        if event_requests:
            ids = [item["id"] for item in event_requests]
            placeholders = ",".join("?" for _ in ids)
            history = db.execute(
                f"SELECT * FROM event_request_history WHERE event_request_id IN ({placeholders}) ORDER BY id DESC",
                ids,
            ).fetchall()
            for entry in history:
                history_by_request.setdefault(entry["event_request_id"], []).append(entry)
    return render_template(
        "root_event_requests.html",
        event_requests=event_requests,
        history_by_request=history_by_request,
    )


@app.route("/root/event-requests/<int:request_id>/review", methods=["POST"])
@root_required
def review_event_request(request_id):
    decision = request.form.get("decision", "")
    root_note = request.form.get("root_note", "").strip()
    if decision not in {"approved", "rejected"}:
        abort(400)
    user = current_user()
    with get_db() as db:
        item = db.execute(
            "SELECT * FROM event_requests WHERE id = ? AND status = 'pending'",
            (request_id,),
        ).fetchone()
        if item is None:
            flash("That request was already reviewed or could not be found.", "error")
            return redirect(url_for("root_event_requests"))
        result = db.execute(
            """UPDATE event_requests
               SET status = ?,
                   root_note = CASE WHEN ? = '' THEN root_note ELSE ? END,
                   reviewed_by = ?, reviewed_at = CURRENT_TIMESTAMP
               WHERE id = ? AND status = 'pending'""",
            (decision, root_note, root_note, user["id"], request_id),
        )
        if result.rowcount == 0:
            flash("That request was already reviewed or could not be found.", "error")
        else:
            record_request_history(db, item, user["id"], decision, root_note=root_note)
            if decision == "approved":
                requester = db.execute("SELECT institution FROM users WHERE id = ?", (item["requester_id"],)).fetchone()
                db.execute(
                    """INSERT OR IGNORE INTO events
                       (event_request_id,event_name,organization_university,event_type,description,start_date,end_date,venue,visibility,status,primary_convener_id)
                       VALUES (?,?,?,'General',?,?,?,?,'PUBLIC','UPCOMING',?)""",
                    (item["id"], item["event_title"], requester["institution"] or "Not specified", item["description"],
                     item["proposed_date"], item["proposed_date"], item["venue"], item["requester_id"]),
                )
            flash(f"Event request {decision}.", "success")
    return redirect(url_for("root_event_requests"))


@app.route("/face-registration", methods=["GET", "POST"])
@login_required
def face_registration():
    user = current_user()
    if request.method == "POST":
        is_capture = request.is_json or bool(request.form.get("image_data"))
        try:
            embedding = generate_embedding(submitted_image())
            with get_db() as db:
                db.execute(
                    "UPDATE users SET face_embedding = ? WHERE id = ?",
                    (json.dumps(embedding.tolist()), user["id"]),
                )
            message = "Face detected. 128-dimensional embedding generated. Registration successful."
            if is_capture:
                return jsonify(ok=True, message=message)
            flash(message, "success")
        except (FaceError, RuntimeError) as error:
            if is_capture:
                return jsonify(ok=False, message=str(error)), 400
            flash(str(error), "error")
        return redirect(url_for("face_registration"))
    return render_template("face_registration.html", user=user)


@app.route("/face-verification", methods=["GET", "POST"])
@login_required
def face_verification():
    user = current_user()
    result = None
    if request.method == "POST":
        is_capture = request.is_json or bool((request.get_json(silent=True) or {}).get("image_data"))
        try:
            if not user["face_embedding"]:
                raise FaceError("Register your face before running verification.")
            probe = generate_embedding(submitted_image())
            similarity, matched = compare_embeddings(json.loads(user["face_embedding"]), probe)
            result = {
                "similarity": similarity,
                "matched": matched,
                "label": "MATCH" if matched else "NO MATCH",
                "threshold": SIMILARITY_THRESHOLD,
            }
            if is_capture:
                return jsonify(ok=True, **result)
        except (FaceError, ValueError, RuntimeError) as error:
            if is_capture:
                return jsonify(ok=False, message=str(error)), 400
            flash(str(error), "error")
    return render_template(
        "face_verification.html",
        user=user,
        result=result,
        threshold=SIMILARITY_THRESHOLD,
    )


if __name__ == "__main__":
    validate_runtime_configuration()
    init_db()
    if len(sys.argv) > 1 and sys.argv[1] == "create-root":
        full_name = input("Root user's full name: ").strip()
        email = input("Root user's email: ").strip().lower()
        password = getpass("Root password (at least 8 characters): ")
        confirmation = getpass("Confirm root password: ")
        if not full_name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise SystemExit("Enter a name and valid email address.")
        if len(password) < 8 or password != confirmation:
            raise SystemExit("Passwords must match and contain at least 8 characters.")
        with get_db() as db:
            existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                db.execute(
                    "UPDATE users SET role = 'root', password_hash = ?, email_verified = 1 WHERE id = ?",
                    (generate_password_hash(password), existing["id"]),
                )
                print(f"Existing account {email} promoted to root; its password was updated.")
            else:
                db.execute(
                    """INSERT INTO users (full_name,email,password_hash,affiliation,role,email_verified)
                       VALUES (?,?,?,'internal','root',1)""",
                    (full_name, email, generate_password_hash(password)),
                )
                print(f"Root account created for {email}.")
    elif len(sys.argv) == 1:
        app.run(debug=os.environ.get("FLASK_DEBUG", "").strip().lower() in {"1", "true", "yes"})
    else:
        raise SystemExit("Usage: python app.py [create-root]")
