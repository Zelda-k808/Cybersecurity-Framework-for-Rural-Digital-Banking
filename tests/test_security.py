import os
import tempfile
import unittest

from app import app, init_db


class SecurityTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        app.config["TESTING"] = True
        app.config["DATABASE"] = self.temp_db.name
        app.config["SECRET_KEY"] = "test-secret"

        with app.app_context():
            init_db()

        self.client = app.test_client()

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
        with self.client.session_transaction() as session_data:
            otp = session_data.get("pending_otp")
        return self.client.post("/verify-otp", data={"otp": otp}, follow_redirects=True)

    def full_login(self):
        self.register_user()
        self.login_password_step()
        return self.complete_otp_step()

    def test_bruteforce_lockout_after_multiple_failures(self):
        self.register_user()
        for _ in range(4):
            response = self.login_password_step(password="WrongPass123")
            self.assertIn(b"Invalid credentials", response.data)

        fifth_attempt = self.login_password_step(password="WrongPass123")
        self.assertIn(b"Too many failed attempts", fifth_attempt.data)

        locked_attempt = self.login_password_step(password="WrongPass123")
        self.assertIn(b"Account temporarily locked", locked_attempt.data)

    def test_sql_injection_payload_cannot_bypass_login(self):
        self.register_user()
        response = self.client.post(
            "/login",
            data={
                "email": "' OR 1=1 --",
                "password": "anything",
            },
            follow_redirects=True,
        )
        self.assertIn(b"Invalid credentials", response.data)
        self.assertNotIn(b"OTP (simulation)", response.data)

    def test_otp_required_before_dashboard_access(self):
        self.register_user()
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


if __name__ == "__main__":
    unittest.main()
