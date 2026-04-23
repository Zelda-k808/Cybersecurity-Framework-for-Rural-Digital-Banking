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
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Auto-load .env file for local development
_env_path = os.path.join(BASE_DIR, ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _, _v = _line.partition("=")
                os.environ.setdefault(_k.strip(), _v.strip())

MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
OTP_EXPIRY_MINUTES = 5
OTP_MAX_ATTEMPTS = 5

LANG_CONTENT = {
    "en": {
        "app_title": "Secure Rural Banking",
        "hero_text": "Safe and simple banking for rural communities.",
        "lang_en": "English", "lang_hi": "हिन्दी", "lang_mr": "मराठी",
        "nav_home": "Home", "nav_dashboard": "Dashboard", "nav_transfer": "Transfer",
        "nav_history": "History", "nav_signup_requests": "Signup Requests",
        "nav_security_logs": "Security Logs", "nav_transaction_logs": "Transaction Logs",
        "nav_logout": "Logout", "register": "Register", "login": "Login",
        "register_title": "Create Account", "full_name_label": "Full Name",
        "email_label": "Email", "password_label": "Password",
        "register_btn": "Submit Registration",
        "register_hint": "Your account will be reviewed by an admin before activation.",
        "login_title": "Sign In", "remember_me_label": "Remember me", "login_btn": "Sign In",
        "otp_title": "Verify OTP", "otp_label": "Enter 6-digit OTP sent to",
        "otp_btn": "Verify", "resend_otp_btn": "Resend OTP",
        "dashboard_title": "Your Dashboard", "welcome_msg": "Welcome back",
        "balance_label": "Account Balance", "account_number_label": "Account Number",
        "transfer_title": "Send Money", "receiver_name_label": "Receiver Name",
        "receiver_account_label": "Receiver Account Number (11 digits)",
        "amount_label": "Amount (INR)", "note_label": "Note (optional)",
        "transfer_btn": "Submit Transfer", "history_title": "Transaction History",
        "admin_requests_title": "Pending Signup Requests",
        "admin_logs_title": "Security Activity Logs",
        "admin_txn_logs_title": "Transaction Logs",
        "approve_btn": "Approve", "reject_btn": "Reject",
        "no_records": "No records found.", "back_btn": "Back",
    },
    "hi": {
        "app_title": "सुरक्षित ग्रामीण बैंकिंग",
        "hero_text": "ग्रामीण समुदायों के लिए सुरक्षित और सरल बैंकिंग।",
        "lang_en": "English", "lang_hi": "हिन्दी", "lang_mr": "मराठी",
        "nav_home": "होम", "nav_dashboard": "डैशबोर्ड", "nav_transfer": "ट्रांसफर",
        "nav_history": "इतिहास", "nav_signup_requests": "पंजीकरण अनुरोध",
        "nav_security_logs": "सुरक्षा लॉग", "nav_transaction_logs": "लेनदेन लॉग",
        "nav_logout": "लॉगआउट", "register": "रजिस्टर करें", "login": "लॉगिन करें",
        "register_title": "खाता बनाएँ", "full_name_label": "पूरा नाम",
        "email_label": "ईमेल", "password_label": "पासवर्ड",
        "register_btn": "पंजीकरण जमा करें",
        "register_hint": "आपका खाता सक्रिय होने से पहले व्यवस्थापक द्वारा समीक्षा की जाएगी।",
        "login_title": "साइन इन करें", "remember_me_label": "मुझे याद रखें", "login_btn": "साइन इन करें",
        "otp_title": "OTP सत्यापित करें", "otp_label": "6-अंकीय OTP दर्ज करें भेजा गया",
        "otp_btn": "सत्यापित करें", "resend_otp_btn": "OTP पुनः भेजें",
        "dashboard_title": "आपका डैशबोर्ड", "welcome_msg": "वापसी पर स्वागत है",
        "balance_label": "खाता शेष", "account_number_label": "खाता संख्या",
        "transfer_title": "पैसे भेजें", "receiver_name_label": "प्राप्तकर्ता का नाम",
        "receiver_account_label": "प्राप्तकर्ता खाता संख्या (11 अंक)",
        "amount_label": "राशि (INR)", "note_label": "नोट (वैकल्पिक)",
        "transfer_btn": "ट्रांसफर जमा करें", "history_title": "लेनदेन इतिहास",
        "admin_requests_title": "लंबित पंजीकरण अनुरोध",
        "admin_logs_title": "सुरक्षा गतिविधि लॉग",
        "admin_txn_logs_title": "लेनदेन लॉग",
        "approve_btn": "स्वीकृत करें", "reject_btn": "अस्वीकार करें",
        "no_records": "कोई रिकॉर्ड नहीं मिला।", "back_btn": "वापस",
    },
    "mr": {
        "app_title": "सुरक्षित ग्रामीण बँकिंग",
        "hero_text": "ग्रामीण समुदायांसाठी सुरक्षित आणि सोपी बँकिंग.",
        "lang_en": "English", "lang_hi": "हिन्दी", "lang_mr": "मराठी",
        "nav_home": "मुख्यपृष्ठ", "nav_dashboard": "डॅशबोर्ड", "nav_transfer": "हस्तांतरण",
        "nav_history": "इतिहास", "nav_signup_requests": "नोंदणी विनंत्या",
        "nav_security_logs": "सुरक्षा नोंदी", "nav_transaction_logs": "व्यवहार नोंदी",
        "nav_logout": "लॉगआउट", "register": "नोंदणी करा", "login": "लॉगिन करा",
        "register_title": "खाते तयार करा", "full_name_label": "पूर्ण नाव",
        "email_label": "ईमेल", "password_label": "पासवर्ड",
        "register_btn": "नोंदणी सादर करा",
        "register_hint": "तुमच्या खात्याचे सक्रियकरणापूर्वी प्रशासकाद्वारे पुनरावलोकन केले जाईल.",
        "login_title": "साइन इन करा", "remember_me_label": "मला लक्षात ठेवा", "login_btn": "साइन इन करा",
        "otp_title": "OTP सत्यापित करा", "otp_label": "पाठवलेला 6-अंकी OTP प्रविष्ट करा",
        "otp_btn": "सत्यापित करा", "resend_otp_btn": "OTP पुन्हा पाठवा",
        "dashboard_title": "तुमचा डॅशबोर्ड", "welcome_msg": "परत आल्याबद्दल स्वागत आहे",
        "balance_label": "खाते शिल्लक", "account_number_label": "खाते क्रमांक",
        "transfer_title": "पैसे पाठवा", "receiver_name_label": "प्राप्तकर्त्याचे नाव",
        "receiver_account_label": "प्राप्तकर्त्याचा खाते क्रमांक (11 अंक)",
        "amount_label": "रक्कम (INR)", "note_label": "नोंद (पर्यायी)",
        "transfer_btn": "हस्तांतरण सादर करा", "history_title": "व्यवहार इतिहास",
        "admin_requests_title": "प्रलंबित नोंदणी विनंत्या",
        "admin_logs_title": "सुरक्षा क्रियाकलाप नोंदी",
        "admin_txn_logs_title": "व्यवहार नोंदी",
        "approve_btn": "मंजूर करा", "reject_btn": "नाकारा",
        "no_records": "कोणतेही रेकॉर्ड सापडले नाहीत.", "back_btn": "मागे",
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
app.config["TRUST_REVERSE_PROXY"] = os.environ.get("TRUST_REVERSE_PROXY", "1") == "1"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["WTF_CSRF_ENABLED"] = True
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

if app.config["TRUST_REVERSE_PROXY"]:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

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
            account_number TEXT UNIQUE,
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
            receiver_account_number TEXT,
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

        CREATE TABLE IF NOT EXISTS signup_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            reviewed_by INTEGER,
            reviewed_at TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transaction_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            txn_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            receiver_account_number TEXT NOT NULL,
            amount REAL NOT NULL,
            note TEXT,
            ip_address TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(txn_id) REFERENCES transactions(id),
            FOREIGN KEY(sender_id) REFERENCES users(id)
        );
        """
    )
    # Migrations for pre-existing databases (ignore if column already exists)
    for migration_sql in [
        "ALTER TABLE users ADD COLUMN account_number TEXT UNIQUE",
        "ALTER TABLE transactions ADD COLUMN receiver_account_number TEXT",
    ]:
        try:
            db.execute(migration_sql)
        except Exception:
            pass
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


def generate_unique_account_number():
    """Generate a unique 11-digit account number (prefix 10 + 9 random digits)."""
    db = get_db()
    while True:
        acc_num = "10" + "".join([str(random.randint(0, 9)) for _ in range(9)])
        existing = db.execute(
            "SELECT id FROM users WHERE account_number = ?", (acc_num,)
        ).fetchone()
        if not existing:
            return acc_num


def log_transaction(txn_id, sender_id, receiver_account_number, amount, note):
    """Write a separate transaction-specific audit record."""
    ip = get_client_ip()
    db = get_db()
    db.execute(
        """
        INSERT INTO transaction_logs
            (txn_id, sender_id, receiver_account_number, amount, note, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (txn_id, sender_id, receiver_account_number, amount, note, ip, now_iso()),
    )
    db.commit()


def get_user_by_email(email):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not row:
        return None
    return User(row["id"], row["full_name"], row["email"], row["password_hash"], row["role"])


def get_pending_signup_by_email(email):
    db = get_db()
    return db.execute(
        """
        SELECT * FROM signup_requests
        WHERE email = ? AND status = 'pending'
        LIMIT 1
        """,
        (email,),
    ).fetchone()


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


def send_email_message(to_email, subject, body):
    if app.config.get("TESTING"):
        app.config["LAST_SENT_EMAIL"] = {"to": to_email, "subject": subject, "body": body}
        return True

    smtp_host = app.config.get("SMTP_HOST")
    smtp_username = app.config.get("SMTP_USERNAME")
    smtp_password = app.config.get("SMTP_PASSWORD")
    if not smtp_host or not smtp_username or not smtp_password:
        logging.error("SMTP not configured. Email delivery failed for %s", to_email)
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = app.config.get("SMTP_FROM")
    message["To"] = to_email
    message.set_content(body)
    try:
        with smtplib.SMTP(smtp_host, app.config.get("SMTP_PORT")) as server:
            if app.config.get("SMTP_USE_TLS"):
                server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(message)
        return True
    except Exception as exc:  # noqa: BLE001
        logging.error("Failed to send email to %s: %s", to_email, exc)
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


@app.after_request
def set_security_headers(response):
    """Prevent browsers from caching pages — stops back-button access after logout."""
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.context_processor
def inject_global_data():
    lang = session.get("lang", "en")
    return {"lang_data": LANG_CONTENT.get(lang, LANG_CONTENT["en"]), "selected_lang": lang}


@app.errorhandler(CSRFError)
def handle_csrf_error(_error):
    flash("Security validation failed. Please retry the action.", "danger")
    return redirect(request.referrer or url_for("home"))


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
        if get_user_by_email(email) or get_pending_signup_by_email(email):
            flash("Email already has an account or pending request.", "warning")
            return redirect(url_for("register"))

        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        db = get_db()
        db.execute(
            """
            INSERT INTO signup_requests (full_name, email, password_hash, status, created_at)
            VALUES (?, ?, ?, 'pending', ?)
            """,
            (full_name, email, password_hash, now_iso()),
        )
        db.commit()
        log_activity(None, "signup_requested", f"Signup request submitted for email={email}")
        flash("Signup request submitted. Wait for admin approval email before login.", "info")
        return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        ip = get_client_ip()
        remember_me = request.form.get("remember_me") == "on"

        if not validators.email(email):
            flash("Enter a valid email address.", "danger")
            return redirect(url_for("login"))

        if get_pending_signup_by_email(email):
            flash("Account approval pending. Please wait for admin email.", "warning")
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
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
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


@app.route("/admin/requests")
@login_required
def admin_requests():
    if current_user.role != "admin":
        flash("Unauthorized. Admin access required.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    pending_requests = db.execute(
        """
        SELECT id, full_name, email, created_at
        FROM signup_requests
        WHERE status = 'pending'
        ORDER BY created_at ASC
        """
    ).fetchall()
    return render_template("admin_requests.html", requests=pending_requests)


@app.route("/admin/requests/<int:request_id>/approve", methods=["POST"])
@login_required
def approve_signup_request(request_id):
    if current_user.role != "admin":
        flash("Unauthorized. Admin access required.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    signup_request = db.execute(
        "SELECT * FROM signup_requests WHERE id = ? AND status = 'pending'",
        (request_id,),
    ).fetchone()
    if not signup_request:
        flash("Request not found or already reviewed.", "warning")
        return redirect(url_for("admin_requests"))

    existing_user = get_user_by_email(signup_request["email"])
    if existing_user:
        db.execute(
            """
            UPDATE signup_requests
            SET status = 'approved', reviewed_by = ?, reviewed_at = ?
            WHERE id = ?
            """,
            (current_user.id, now_iso(), request_id),
        )
        db.commit()
        flash("User already existed. Request marked approved.", "info")
        return redirect(url_for("admin_requests"))

    acc_num = generate_unique_account_number()
    db.execute(
        """
        INSERT INTO users (full_name, email, password_hash, role, account_number, created_at)
        VALUES (?, ?, ?, 'customer', ?, ?)
        """,
        (
            signup_request["full_name"],
            signup_request["email"],
            signup_request["password_hash"],
            acc_num,
            now_iso(),
        ),
    )
    db.execute(
        """
        UPDATE signup_requests
        SET status = 'approved', reviewed_by = ?, reviewed_at = ?
        WHERE id = ?
        """,
        (current_user.id, now_iso(), request_id),
    )
    db.commit()
    log_activity(current_user.id, "signup_approved", f"Approved signup for email={signup_request['email']}")

    sent = send_email_message(
        signup_request["email"],
        "Your account has been approved",
        (
            f"Hello {signup_request['full_name']},\n\n"
            "Your account creation request has been approved. "
            "You can now sign in to the banking portal.\n\n"
            "Regards,\nAdmin Team"
        ),
    )
    if sent:
        flash("Signup approved and email sent to user.", "success")
    else:
        flash("Signup approved, but approval email failed to send.", "warning")
    return redirect(url_for("admin_requests"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    row = db.execute("SELECT balance, account_number FROM users WHERE id = ?", (current_user.id,)).fetchone()
    balance = row["balance"] if row else 0
    account_number = row["account_number"] if row else None
    return render_template("dashboard.html", balance=balance, account_number=account_number)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    if request.method == "POST":
        receiver_name = request.form.get("receiver", "").strip()
        receiver_account = request.form.get("receiver_account", "").strip()
        amount_raw = request.form.get("amount", "").strip()
        note = request.form.get("note", "").strip()

        receiver_error = validate_safe_text(receiver_name, "Receiver name", max_len=80)
        if receiver_error:
            flash(receiver_error, "danger")
            return redirect(url_for("transfer"))

        if not re.fullmatch(r"\d{11}", receiver_account):
            flash("Receiver account number must be exactly 11 digits.", "danger")
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
        sender_row = db.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()

        if sender_row and sender_row["account_number"] == receiver_account:
            flash("You cannot transfer to your own account.", "danger")
            return redirect(url_for("transfer"))

        receiver_row = db.execute(
            "SELECT * FROM users WHERE account_number = ?", (receiver_account,)
        ).fetchone()
        if not receiver_row:
            flash("Receiver account number not found.", "danger")
            return redirect(url_for("transfer"))

        current_balance = sender_row["balance"] if sender_row else 0
        if amount > current_balance:
            flash("Insufficient balance.", "danger")
            return redirect(url_for("transfer"))

        db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, current_user.id))
        db.execute("UPDATE users SET balance = balance + ? WHERE account_number = ?",
                   (amount, receiver_account))
        cursor = db.execute(
            """
            INSERT INTO transactions
                (user_id, txn_type, amount, receiver_name, receiver_account_number, note, created_at)
            VALUES (?, 'debit', ?, ?, ?, ?, ?)
            """,
            (current_user.id, amount, receiver_name, receiver_account, note, now_iso()),
        )
        txn_id = cursor.lastrowid
        db.commit()
        log_transaction(txn_id, current_user.id, receiver_account, amount, note)
        log_activity(
            current_user.id, "transfer_success",
            f"Transferred {amount:.2f} to account {receiver_account} ({receiver_name})"
        )
        flash("Transfer successful.", "success")
        return redirect(url_for("history"))

    return render_template("transfer.html")


@app.route("/history")
@login_required
def history():
    db = get_db()
    rows = db.execute(
        """
        SELECT txn_type, amount, receiver_name, receiver_account_number, note, created_at
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


@app.route("/admin/transaction-logs")
@login_required
def admin_transaction_logs():
    if current_user.role != "admin":
        flash("Unauthorized. Admin access required.", "danger")
        return redirect(url_for("dashboard"))

    db = get_db()
    rows = db.execute(
        """
        SELECT tl.id, u.full_name AS sender_name, tl.receiver_account_number,
               tl.amount, tl.note, tl.ip_address, tl.created_at
        FROM transaction_logs tl
        LEFT JOIN users u ON tl.sender_id = u.id
        ORDER BY tl.created_at DESC
        LIMIT 200
        """
    ).fetchall()
    return render_template("admin_transaction_logs.html", logs=rows)


@app.route("/logout")
@login_required
def logout():
    log_activity(current_user.id, "logout", "User logged out")
    logout_user()
    flash("You have logged out.", "info")
    return redirect(url_for("home"))


if __name__ == "__main__":
    # uWSGI is Linux-only; use Flask dev server on Windows
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["REMEMBER_COOKIE_SECURE"] = False
    app.run(debug=True, host="127.0.0.1", port=5000)
