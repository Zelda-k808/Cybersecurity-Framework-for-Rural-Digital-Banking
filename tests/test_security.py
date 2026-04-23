import os
import tempfile
import unittest
from datetime import datetime, timezone

from app import OTP_MAX_ATTEMPTS, app, bcrypt, init_db


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

    def create_user_directly(self, name="Test User", email="test@example.com", password="StrongPass123", role="customer"):
        password_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        import random
        account_number = str(random.randint(10_000_000_000, 99_999_999_999))
        with app.app_context():
            db_path = app.config["DATABASE"]
            import sqlite3
            db = sqlite3.connect(db_path)
            db.execute(
                """
                INSERT INTO users (full_name, email, password_hash, role, account_number, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, email, password_hash, role, account_number, datetime.now(timezone.utc).isoformat()),
            )
            db.commit()
            db.close()

    def tearDown(self):
        try:
            os.unlink(self.temp_db.name)
        except FileNotFoundError:
            pass

    def register_user(self, name="Test User", email="test@example.com", password="StrongPass123"):
        return self.client.post(
            "/register",
            data={
                "full_name": name,
                "email": email,
                "password": password,
            },
            follow_redirects=True,
        )

    def login_password_step(self, email="test@example.com", password="StrongPass123"):
        return self.client.post(
            "/login",
            data={
                "email": email,
                "password": password,
            },
            follow_redirects=True,
        )

    def complete_otp_step(self):
        otp = app.config.get("LAST_SENT_OTP")
        return self.client.post("/verify-otp", data={"otp": otp}, follow_redirects=True)

    def full_login(self):
        self.create_user_directly()
        self.login_password_step()
        return self.complete_otp_step()

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

    def test_otp_required_before_dashboard_access(self):
        self.create_user_directly()
        self.login_password_step()
        response = self.client.get("/dashboard", follow_redirects=True)
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

    def test_otp_retry_limit_enforced(self):
        self.create_user_directly()
        self.login_password_step()
        for _ in range(OTP_MAX_ATTEMPTS):
            response = self.client.post("/verify-otp", data={"otp": "000000"}, follow_redirects=True)
        self.assertIn(b"Incorrect OTP", response.data)

        final_response = self.client.post("/verify-otp", data={"otp": "000000"}, follow_redirects=True)
        self.assertIn(b"Too many OTP failures", final_response.data)

    def test_signup_creates_pending_request_not_active_user(self):
        response = self.register_user()
        self.assertIn(b"Signup request submitted", response.data)

        login_response = self.login_password_step()
        self.assertIn(b"Account approval pending", login_response.data)


if __name__ == "__main__":
    unittest.main()
