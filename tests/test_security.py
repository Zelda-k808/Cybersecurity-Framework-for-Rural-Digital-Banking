import os
import tempfile
import unittest
from datetime import datetime, timezone

import pyotp

from app import OTP_MAX_ATTEMPTS, app, generate_totp_secret, hash_password, init_db


class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        app.config["TESTING"] = True
        app.config["DATABASE"] = self.temp_db.name
        app.config["SECRET_KEY"] = "test-secret"
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["SESSION_COOKIE_SECURE"] = False
        app.config["REMEMBER_COOKIE_SECURE"] = False

        with app.app_context():
            init_db()

        self.client = app.test_client()

    def create_user_directly(self, name="Test User", email="test@example.com", password="StrongPass123!", role="customer"):
        password_hash = hash_password(password)
        totp_secret = generate_totp_secret()
        import random
        account_number = str(random.randint(10_000_000_000, 99_999_999_999))
        with app.app_context():
            db_path = app.config["DATABASE"]
            import sqlite3
            db = sqlite3.connect(db_path)
            db.execute(
                """
                INSERT INTO users (full_name, email, password_hash, role, account_number, totp_secret, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (name, email, password_hash, role, account_number, totp_secret, datetime.now(timezone.utc).isoformat()),
            )
            db.commit()
            db.close()

    def tearDown(self):
        try:
            os.unlink(self.temp_db.name)
        except FileNotFoundError:
            pass

    def register_user(self, name="Test User", email="test@example.com", password="StrongPass123!"):
        return self.client.post(
            "/register",
            data={
                "full_name": name,
                "email": email,
                "password": password,
            },
            follow_redirects=True,
        )

    def login_password_step(self, email="test@example.com", password="StrongPass123!"):
        return self.client.post(
            "/login",
            data={
                "email": email,
                "password": password,
            },
            follow_redirects=True,
        )


    def complete_email_otp_step(self, email="test@example.com"):
        otp_code = app.config.get("LAST_SENT_OTP", "000000")
        return self.client.post("/verify-otp", data={"otp": otp_code}, follow_redirects=True)

    def complete_totp_step(self, email="test@example.com"):
        with app.app_context():
            db_path = app.config["DATABASE"]
            import sqlite3
            db = sqlite3.connect(db_path)
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT totp_secret FROM users WHERE email = ?", (email,)).fetchone()
            db.close()
            totp_secret = row["totp_secret"] if row else ""
        totp_code = pyotp.TOTP(totp_secret).now()
        return self.client.post("/verify-totp", data={"totp": totp_code}, follow_redirects=True)

    def full_login(self):
        self.create_user_directly()
        self.login_password_step()
        self.complete_email_otp_step()
        return self.complete_totp_step()

    def test_bruteforce_lockout_after_multiple_failures(self):
        self.create_user_directly()
        for _ in range(4):
            response = self.login_password_step(password="WrongPass123")
            self.assertIn(b"Invalid credentials", response.data)

        fifth_attempt = self.login_password_step(password="WrongPass123")
        self.assertIn(b"Too many failed attempts", fifth_attempt.data)

        locked_attempt = self.login_password_step(password="WrongPass123")
        self.assertIn(b"Account temporarily locked", locked_attempt.data)

    def test_sql_injection_payload_cannot_bypass_login(self):
        self.create_user_directly()
        response = self.client.post(
            "/login",
            data={
                "email": "test@example.com",
                "password": "' OR 1=1 --",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Invalid credentials", response.data)
        self.assertNotIn(b"Login successful", response.data)

    def test_totp_required_before_dashboard_access(self):
        self.create_user_directly()
        self.login_password_step()
        response = self.client.get("/dashboard", follow_redirects=True)
        # User is not authenticated until TOTP is verified, so dashboard redirects to login
        self.assertIn(b"Login", response.data)
        self.assertNotIn(b"Dashboard", response.data)

    def test_transfer_input_sanitization_blocks_injection_patterns(self):
        self.full_login()
        response = self.client.post(
            "/transfer",
            data={
                "receiver": "Robert'); DROP TABLE users;--",
                "amount": "10",
                "note": "safe note",
            },
            follow_redirects=True,
        )
        self.assertIn(b"contains unsupported characters", response.data)

    def test_totp_rejects_invalid_code(self):
        self.create_user_directly()
        self.login_password_step()
        self.complete_email_otp_step()
        response = self.client.post("/verify-totp", data={"totp": "000000"}, follow_redirects=True)
        self.assertIn(b"Invalid TOTP code", response.data)

    def test_signup_creates_pending_request_not_active_user(self):
        response = self.register_user()
        self.assertIn(b"Signup request submitted", response.data)

        login_response = self.login_password_step()
        self.assertIn(b"Account approval pending", login_response.data)

    def test_csrf_protection_is_active_on_all_forms(self):
        """CSRF protection must be active: CSRFProtect must be registered on the
        app and every POST form must contain a hidden csrf_token input field."""
        # 1 — middleware level: CSRFProtect must be registered on the app
        self.assertIn(
            "csrf",
            app.extensions,
            "CSRFProtect is not registered on the app — CSRF protection is missing",
        )

        # 2 — form level: the rendered login page must contain a csrf_token field
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'name="csrf_token"',
            response.data,
            "Login form does not contain a CSRF token hidden input",
        )

        # 3 — form level: the register page must also contain a csrf_token field
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b'name="csrf_token"',
            response.data,
            "Register form does not contain a CSRF token hidden input",
        )




    def test_customer_cannot_access_admin_routes(self):
        """Authenticated customers must be denied access to all admin-only routes."""
        self.full_login()
        admin_routes = ["/admin/logs", "/admin/requests", "/admin/transaction-logs"]
        for route in admin_routes:
            response = self.client.get(route, follow_redirects=True)
            self.assertIn(
                b"Unauthorized",
                response.data,
                msg=f"Customer was not denied access to {route}",
            )

    def test_no_store_cache_headers_on_authenticated_responses(self):
        """Every authenticated response must carry Cache-Control: no-store to
        prevent the browser from caching sensitive pages."""
        self.full_login()
        for route in ["/dashboard", "/transfer", "/history"]:
            response = self.client.get(route)
            cache_control = response.headers.get("Cache-Control", "")
            self.assertIn(
                "no-store",
                cache_control,
                msg=f"Cache-Control: no-store missing on {route} (got: {cache_control!r})",
            )

    def test_transfer_to_own_account_is_rejected(self):
        """Users must not be able to transfer money to their own account number."""
        self.full_login()
        import sqlite3
        db = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT account_number FROM users WHERE email = ?",
            ("test@example.com",),
        ).fetchone()
        own_account = row["account_number"]
        db.close()

        response = self.client.post(
            "/transfer",
            data={
                "receiver": "Test User",
                "receiver_account": own_account,
                "amount": "100",
                "note": "self transfer attempt",
            },
            follow_redirects=True,
        )
        # exact flash message from app.py line 943
        self.assertIn(b"You cannot transfer to your own account.", response.data)

    def test_transfer_with_insufficient_balance_is_rejected(self):
        """Transfer amount exceeding the sender's balance must be rejected.
        A second receiver user must exist so the route reaches the balance check.
        """
        self.full_login()
        # Create a second user to act as receiver so the account lookup succeeds
        self.create_user_directly(
            name="Receiver",
            email="receiver@example.com",
            password="ReceiverPass123",
            role="customer",
        )
        import sqlite3
        db = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        row = db.execute(
            "SELECT account_number FROM users WHERE email = ?",
            ("receiver@example.com",),
        ).fetchone()
        receiver_account = row["account_number"]
        db.close()

        response = self.client.post(
            "/transfer",
            data={
                "receiver": "Receiver",
                "receiver_account": receiver_account,
                "amount": "99999999",  # far exceeds default 5000.00 balance
                "note": "overdraft attempt",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Insufficient balance.", response.data)


if __name__ == "__main__":
    unittest.main()
