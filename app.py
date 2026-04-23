import logging
import os
import random
import re
import sqlite3
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import validators
from click import echo
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
OTP_EXPIRY_MINUTES = 5
OTP_MAX_ATTEMPTS = 5

LANG_CONTENT = {
    "en": {
        "app_title": "Secure Rural Banking",
        "hero_text": "Safe and simple banking for rural communities.",
        "register": "Register",
        "login": "Login",
    },
    "hi": {
        "app_title": "सुरक्षित ग्रामीण बैंकिंग",
        "hero_text": "ग्रामीण समुदायों के लिए सुरक्षित और सरल बैंकिंग।",
        "register": "रजिस्टर करें",
        "login": "लॉगिन करें",
    },
    "mr": {
        "app_title": "सुरक्षित ग्रामीण बँकिंग",
        "hero_text": "ग्रामीण समुदायांसाठी सुरक्षित आणि सोपी बँकिंग.",
        "register": "नोंदणी करा",
        "login": "लॉगिन करा",
    },
}


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")
app.config["DATABASE"] = os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "banking.db"))
app.config["SMTP_HOST"] = os.environ.get("SMTP_HOST", "")
app.config["SMTP_PORT"] = int(os.environ.get("SMTP_PORT", "587"))
app.config["SMTP_USERNAME"] = os.environ.get("SMTP_USERNAME", "")
app.config["SMTP_PASSWORD"] = os.environ.get("SMTP_PASSWORD", "")
app.config["SMTP_FROM"] = os.environ.get("SMTP_FROM", "noreply@ruralbank.local")
app.config["SMTP_USE_TLS"] = os.environ.get("SMTP_USE_TLS", "1") == "1"
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(BASE_DIR, "security.log")),
        logging.StreamHandler(),
    ],
)


class User(UserMixin):
    def __init__(self, user_id, full_name, email, password_hash, role):
        self.id = str(user_id)
        self.full_name = full_name
        self.email = email
        self.password_hash = password_hash
        self.role = role


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            balance REAL NOT NULL DEFAULT 5000.00,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            failed_count INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            last_attempt TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            txn_type TEXT NOT NULL,
            amount REAL NOT NULL,
            receiver_name TEXT,
            note TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS otp_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            consumed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        """
    )
    db.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def validate_safe_text(value, field_name, max_len=80):
    if not value or len(value) > max_len:
        return f"{field_name} is required and should be under {max_len} characters."
    if not re.match(r"^[a-zA-Z0-9 .,_-]+$", value):
        return f"{field_name} contains unsupported characters."
    return None


def validate_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must include at least one digit."
    return None


def log_activity(user_id, event_type, description):
    ip = get_client_ip()
    logging.info("[%s] user=%s ip=%s %s", event_type, user_id, ip, description)
    db = get_db()
    db.execute(
        """
        INSERT INTO activity_logs (user_id, event_type, ip_address, description, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, event_type, ip, description, now_iso()),
    )
    db.commit()


def get_user_by_email(email):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        return None
    return User(row["id"], row["full_name"], row["email"], row["password_hash"], row["role"])


def clear_pending_auth():
    session.pop("pending_user_email", None)


def send_otp(email, otp_code):
    if app.config.get("TESTING"):
        app.config["LAST_SENT_OTP"] = otp_code
        return True

    smtp_host = app.config.get("SMTP_HOST")
    smtp_username = app.config.get("SMTP_USERNAME")
    smtp_password = app.config.get("SMTP_PASSWORD")

    if not smtp_host or not smtp_username or not smtp_password:
        logging.error("SMTP not configured. OTP delivery failed for %s", email)
        return False

    message = EmailMessage()
    message["Subject"] = "Your Rural Banking OTP"
    message["From"] = app.config.get("SMTP_FROM")
    message["To"] = email
    message.set_content(
        f"Your one-time password is {otp_code}. It expires in {OTP_EXPIRY_MINUTES} minutes."
    )

    try:
        with smtplib.SMTP(smtp_host, app.config.get("SMTP_PORT")) as server:
            if app.config.get("SMTP_USE_TLS"):
                server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(message)
        return True
    except Exception as exc:  # noqa: BLE001
        logging.error("Failed to send OTP email to %s: %s", email, exc)
        return False


def issue_otp_challenge(email):
    otp_code = f"{random.randint(100000, 999999)}"
    delivered = send_otp(email, otp_code)
    if not delivered:
        return False

    otp_hash = bcrypt.generate_password_hash(otp_code).decode("utf-8")
    db = get_db()
    db.execute("DELETE FROM otp_challenges WHERE email = ? AND consumed = 0", (email,))
    db.execute(
        """
        INSERT INTO otp_challenges (email, otp_hash, expires_at, attempts, consumed, created_at)
        VALUES (?, ?, ?, 0, 0, ?)
        """,
        (
            email,
            otp_hash,
            (datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat(),
            now_iso(),
        ),
    )
    db.commit()
    return True


def get_active_otp_challenge(email):
    db = get_db()
    return db.execute(
        """
        SELECT * FROM otp_challenges
        WHERE email = ? AND consumed = 0
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (email,),
    ).fetchone()


def create_admin_user(full_name, email, password):
    existing = get_user_by_email(email)
    if existing:
        return False, "Admin already exists with this email."

    password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    db = get_db()
    db.execute(
        """
        INSERT INTO users (full_name, email, password_hash, role, created_at)
        VALUES (?, ?, ?, 'admin', ?)
        """,
        (full_name, email, password_hash, now_iso()),
    )
    db.commit()
    return True, "Admin user created successfully."


@app.cli.command("seed-admin")
def seed_admin():
    full_name = os.environ.get("ADMIN_NAME", "Project Admin")
    email = os.environ.get("ADMIN_EMAIL", "admin@ruralbank.local").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD", "Admin@12345")

    with app.app_context():
        init_db()
        created, message = create_admin_user(full_name, email, password)
        echo(message)
        if created:
            echo(f"Email: {email}")
            echo("Use ADMIN_PASSWORD env var to set a custom password.")


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        return None
    return User(row["id"], row["full_name"], row["email"], row["password_hash"], row["role"])


def is_locked(email, ip_address):
    db = get_db()
    row = db.execute(
        "SELECT * FROM login_attempts WHERE username = ? AND ip_address = ?",
        (email, ip_address),
    ).fetchone()

    if row and row["locked_until"]:
        lock_until = datetime.fromisoformat(row["locked_until"])
        if datetime.now(timezone.utc) < lock_until:
            return True, f"Account temporarily locked until {lock_until.strftime('%H:%M:%S')} UTC."
    return False, None


def record_login_attempt(email, ip_address, success):
    db = get_db()
    row = db.execute(
        "SELECT * FROM login_attempts WHERE username = ? AND ip_address = ?",
        (email, ip_address),
    ).fetchone()

    if success:
        if row:
            db.execute("DELETE FROM login_attempts WHERE id = ?", (row["id"],))
            db.commit()
        return True, None

    failed_count = 1
    lock_until = None
    if row:
        failed_count = row["failed_count"] + 1
    if failed_count >= MAX_FAILED_ATTEMPTS:
        lock_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)).isoformat()

    if row:
        db.execute(
            """
            UPDATE login_attempts
            SET failed_count = ?, locked_until = ?, last_attempt = ?
            WHERE id = ?
            """,
            (failed_count, lock_until, now_iso(), row["id"]),
        )
    else:
        db.execute(
            """
            INSERT INTO login_attempts (username, ip_address, failed_count, locked_until, last_attempt)
            VALUES (?, ?, ?, ?, ?)
            """,
            (email, ip_address, failed_count, lock_until, now_iso()),
        )
    db.commit()

    if lock_until:
        return False, "Too many failed attempts. You are blocked for 15 minutes."
    return True, "Invalid credentials."


@app.before_request
def boot():
    init_db()


@app.context_processor
def inject_global_data():
    lang = session.get("lang", "en")
    return {"lang_data": LANG_CONTENT.get(lang, LANG_CONTENT["en"]), "selected_lang": lang}


@app.route("/set-language/<lang>")
def set_language(lang):
    if lang in LANG_CONTENT:
        session["lang"] = lang
    return redirect(request.referrer or url_for("home"))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not full_name or len(full_name) > 100:
            flash("Full name is required (max 100 chars).", "danger")
            return redirect(url_for("register"))
        if not validators.email(email):
            flash("Enter a valid email address.", "danger")
            return redirect(url_for("register"))
        password_error = validate_password_strength(password)
        if password_error:
            flash(password_error, "danger")
            return redirect(url_for("register"))
        if get_user_by_email(email):
            flash("Email already registered.", "warning")
            return redirect(url_for("register"))

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        db = get_db()
        db.execute(
            """
            INSERT INTO users (full_name, email, password_hash, role, created_at)
            VALUES (?, ?, ?, 'customer', ?)
            """,
            (full_name, email, password_hash, now_iso()),
        )
        db.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        ip = get_client_ip()
        remember_me = request.form.get("remember_me") == "on"

        if not validators.email(email):
            flash("Enter a valid email address.", "danger")
            return redirect(url_for("login"))

        user = get_user_by_email(email)
        locked, lock_message = is_locked(email, ip)
        if locked and lock_message:
            log_activity(None, "auth_lockout", f"Lockout for email={email}")
            flash(lock_message, "danger")
            return redirect(url_for("login"))

        if not user or not bcrypt.check_password_hash(user.password_hash, password):
            clear_pending_auth()
            can_stay, message = record_login_attempt(email, ip, success=False)
            log_activity(None, "auth_failed", f"Failed login for email={email}")
            flash(message if message else "Invalid credentials.", "danger")
            if not can_stay:
                flash("Suspicious activity detected, temporary block applied.", "warning")
            return redirect(url_for("login"))

        record_login_attempt(email, ip, success=True)
        session["pending_user_email"] = user.email
        session["pending_remember_me"] = remember_me

        delivered = issue_otp_challenge(user.email)
        log_activity(user.id, "otp_generated", "OTP generated for second-factor login")
        if delivered:
            flash("OTP sent to your registered email.", "info")
        else:
            clear_pending_auth()
            session.pop("pending_remember_me", None)
            flash("OTP delivery failed. Please contact admin.", "danger")
            return redirect(url_for("login"))
        return redirect(url_for("verify_otp"))

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("pending_user_email")

    if not email:
        flash("Session expired. Please login again.", "warning")
        return redirect(url_for("login"))

    challenge = get_active_otp_challenge(email)
    if not challenge:
        clear_pending_auth()
        flash("No active OTP challenge found. Please login again.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        submitted = request.form.get("otp", "").strip()
        if not re.fullmatch(r"\d{6}", submitted):
            flash("OTP must be a 6-digit code.", "danger")
            return redirect(url_for("verify_otp"))

        if datetime.now(timezone.utc) > datetime.fromisoformat(challenge["expires_at"]):
            db = get_db()
            db.execute("UPDATE otp_challenges SET consumed = 1 WHERE id = ?", (challenge["id"],))
            db.commit()
            clear_pending_auth()
            flash("OTP expired. Login again.", "danger")
            return redirect(url_for("login"))

        if challenge["attempts"] >= OTP_MAX_ATTEMPTS:
            db = get_db()
            db.execute("UPDATE otp_challenges SET consumed = 1 WHERE id = ?", (challenge["id"],))
            db.commit()
            clear_pending_auth()
            flash("Too many OTP failures. Login again.", "danger")
            return redirect(url_for("login"))

        if not bcrypt.check_password_hash(challenge["otp_hash"], submitted):
            db = get_db()
            db.execute(
                "UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?",
                (challenge["id"],),
            )
            db.commit()
            log_activity(None, "otp_failed", f"OTP verification failed for email={email}")
            flash("Incorrect OTP.", "danger")
            return redirect(url_for("verify_otp"))

        user = get_user_by_email(email)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("login"))

        db = get_db()
        previous_login = db.execute(
            """
            SELECT ip_address FROM activity_logs
            WHERE user_id = ? AND event_type = 'login_success'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user.id,),
        ).fetchone()
        current_ip = get_client_ip()
        if previous_login and previous_login["ip_address"] != current_ip:
            log_activity(
                user.id,
                "anomaly_detected",
                f"Login IP changed from {previous_login['ip_address']} to {current_ip}",
            )
            flash("Alert: Login detected from a new location/IP.", "warning")

        db.execute("UPDATE otp_challenges SET consumed = 1 WHERE id = ?", (challenge["id"],))
        db.commit()

        login_user(user, remember=session.get("pending_remember_me", False))
        session.pop("pending_remember_me", None)
        clear_pending_auth()
        log_activity(user.id, "login_success", "User logged in with OTP")
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))

    return render_template("verify_otp.html", email=email)


@app.route("/resend-otp", methods=["POST"])
def resend_otp():
    email = session.get("pending_user_email")
    if not email:
        flash("Login session expired. Please login again.", "warning")
        return redirect(url_for("login"))

    challenge = get_active_otp_challenge(email)
    if challenge and datetime.now(timezone.utc) < datetime.fromisoformat(challenge["expires_at"]):
        # Do not allow spamming OTP generation while one is still active.
        flash("An OTP is already active. Please use it or wait until it expires.", "warning")
        return redirect(url_for("verify_otp"))

    delivered = issue_otp_challenge(email)
    user = get_user_by_email(email)
    if user:
        log_activity(user.id, "otp_resent", "OTP re-issued for login")
    if delivered:
        flash("A new OTP has been sent.", "info")
    else:
        flash("OTP delivery failed. Please contact admin.", "danger")
    return redirect(url_for("verify_otp"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    row = db.execute("SELECT balance FROM users WHERE id = ?", (current_user.id,)).fetchone()
    balance = row["balance"] if row else 0
    return render_template("dashboard.html", balance=balance)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    if request.method == "POST":
        receiver = request.form.get("receiver", "").strip()
        amount_raw = request.form.get("amount", "").strip()
        note = request.form.get("note", "").strip()

        receiver_error = validate_safe_text(receiver, "Receiver name", max_len=80)
        if receiver_error:
            flash(receiver_error, "danger")
            return redirect(url_for("transfer"))

        if note:
            note_error = validate_safe_text(note, "Note", max_len=120)
            if note_error:
                flash(note_error, "danger")
                return redirect(url_for("transfer"))

        try:
            amount = float(amount_raw)
            if amount <= 0:
                raise ValueError
        except ValueError:
            flash("Enter a valid transfer amount.", "danger")
            return redirect(url_for("transfer"))

        db = get_db()
        row = db.execute("SELECT balance FROM users WHERE id = ?", (current_user.id,)).fetchone()
        current_balance = row["balance"] if row else 0

        if amount > current_balance:
            flash("Insufficient balance.", "danger")
            return redirect(url_for("transfer"))

        new_balance = current_balance - amount
        db.execute("UPDATE users SET balance = ? WHERE id = ?", (new_balance, current_user.id))
        db.execute(
            """
            INSERT INTO transactions (user_id, txn_type, amount, receiver_name, note, created_at)
            VALUES (?, 'debit', ?, ?, ?, ?)
            """,
            (current_user.id, amount, receiver, note, now_iso()),
        )
        db.commit()
        log_activity(current_user.id, "transfer_success", f"Transferred {amount:.2f} to {receiver}")
        flash("Transfer successful.", "success")
        return redirect(url_for("history"))

    return render_template("transfer.html")


@app.route("/history")
@login_required
def history():
    db = get_db()
    rows = db.execute(
        """
        SELECT txn_type, amount, receiver_name, note, created_at
        FROM transactions
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (current_user.id,),
    ).fetchall()
    return render_template("history.html", transactions=rows)


@app.route("/admin/logs")
@login_required
def admin_logs():
    if current_user.role != "admin":
        flash("Unauthorized. Admin access required.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    rows = db.execute(
        """
        SELECT user_id, event_type, ip_address, description, created_at
        FROM activity_logs
        ORDER BY created_at DESC
        LIMIT 100
        """
    ).fetchall()
    return render_template("admin_logs.html", logs=rows)


@app.route("/logout")
@login_required
def logout():
    log_activity(current_user.id, "logout", "User logged out")
    logout_user()
    flash("You have logged out.", "info")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
