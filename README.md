# Cybersecurity-Framework-for-Rural-Digital-Banking

A Cybersecurity-driven rural digital banking solution that combines secure system architecture, network monitoring, and penetration testing concepts to enable safe accessible financial services for underserved communities.

## Project Objective

Build a simple web banking app for rural users that is easy to use and hard to attack.

The system is designed for:
- low technical literacy users
- unstable internet conditions
- high fraud/phishing exposure
- strong security with simple UI

## Core Modules Implemented

### A) Secure System Architecture
- Frontend: HTML + CSS + Jinja templates (large buttons, clean screens)
- Backend: Python Flask
- Database: SQLite
- Security controls:
  - password hashing using `Flask-Bcrypt` (bcrypt)
  - admin approval workflow for new account creation
  - OTP-based second-factor login (email delivery)
  - role-based authorization (`customer`, `admin`)
  - session-based auth (`Flask-Login`)
  - HTTPS-only secure session cookies (`Secure`, `HttpOnly`, `SameSite=Lax`)
  - CSRF protection on all POST endpoints (`Flask-WTF` CSRF middleware)
  - input validation and sanitization for transaction fields

### B) Network Monitoring / Suspicious Activity Detection
- logs login and security activity with:
  - timestamp
  - IP address
  - event type
  - short description
- detects and handles:
  - repeated failed login attempts
  - temporary lockout after 5 failures (15 minutes)
  - unusual login IP changes (anomaly warning)
- persistent records stored in `activity_logs` table
- file logging in `security.log` for audit trail

### C) Penetration Testing Scope (for evaluation)
The app is built to demonstrate mitigation of:
- SQL Injection:
  - all DB operations use parameterized queries (`?` placeholders)
- Brute-force login:
  - login attempt tracking by email + IP
  - auto lockout after threshold
- Weak auth flow:
  - password is never stored in plaintext
  - OTP verification required before full login
- Input abuse:
  - transfer fields validated with strict regex and length checks

### D) Rural-Friendly Features
- simple, high-contrast interface
- large touch-friendly controls
- multilingual switch:
  - English (`EN`)
  - Hindi (`HI`)
  - Marathi (`MR`)
- email OTP delivery with production-ready SMTP configuration

## Functional Features
- user registration request queue (pending until admin approval)
- login with password + OTP verification
- check account balance
- money transfer with secure input validation and audit logging
- transaction history
- admin dashboard to approve signup requests
- account approval email notification to user
- admin-only security logs view (`/admin/logs`)

## Tech Stack
- Python 3.x
- Flask
- Flask-Login
- Flask-Bcrypt
- Flask-WTF
- validators
- SQLite

## Project Structure

```text
Cybersecurity-Framework-for-Rural-Digital-Banking/
├── app.py
├── requirements.txt
├── security.log                 # generated at runtime
├── banking.db                   # generated at runtime
├── static/
│   └── style.css
└── templates/
    ├── base.html
    ├── admin_requests.html
    ├── index.html
    ├── register.html
    ├── login.html
    ├── verify_otp.html
    ├── dashboard.html
    ├── transfer.html
    ├── history.html
    └── admin_logs.html
```

## Setup and Run

1. Clone repository
2. Create and activate virtual environment
3. Install dependencies
4. Run app with uWSGI

```bash
pip install -r requirements.txt
uwsgi --ini uwsgi.ini
```

Then open: [http://127.0.0.1:8000](http://127.0.0.1:8000)

### Windows Development Fallback (Waitress)

`uWSGI` is intended for Linux/Unix environments.  
For local development/testing on Windows, run the same Flask app with `waitress`:

```bash
pip install waitress
waitress-serve --listen=127.0.0.1:8000 app:app
```

### Production Preparation Script (Windows)

To prepare dependencies before Linux production deployment, run:

```bat
deploy_production.bat
```

What this script does:
- installs dependencies from `requirements.txt`
- removes `waitress` (Windows dev fallback server), if present
- keeps `Flask` installed because the application code depends on Flask

### Linux Production Runtime (uWSGI)

Use `uWSGI` for production deployment on Linux:

```bash
uwsgi --ini uwsgi.ini
```

Important: `uWSGI` replaces the development server, not the Flask framework.  
So Flask must remain installed for `app:app` to run.

### OTP Delivery Configuration (Email)

Set these environment variables to enable actual OTP sending:

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@example.com
SMTP_PASSWORD=your_app_password
SMTP_FROM=your_email@example.com
SMTP_USE_TLS=1
```

If SMTP is not configured, OTP delivery is blocked and login cannot proceed.

### Security Hardening Configuration

The app enforces production-grade cookie and request protections:

- `SESSION_COOKIE_SECURE=True`
- `SESSION_COOKIE_HTTPONLY=True`
- `SESSION_COOKIE_SAMESITE=Lax`
- `REMEMBER_COOKIE_SECURE=True`
- `REMEMBER_COOKIE_HTTPONLY=True`
- `REMEMBER_COOKIE_SAMESITE=Lax`
- CSRF tokens required for all POST forms via `Flask-WTF`

Important: because `Secure` cookies are enforced, deploy behind HTTPS in production.

### Reverse Proxy Deployment (Nginx + TLS + ProxyFix)

This project is ready to run behind Nginx with TLS termination.

1. Flask app already enables `ProxyFix` in `app.py` and trusts one upstream proxy hop.
2. Keep `TRUST_REVERSE_PROXY=1` (default) in production.
3. Run app with `uWSGI` on localhost.
4. Let Nginx handle HTTPS and forward proxy headers.

Example Nginx server block:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Port $server_port;
    }
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}
```

Recommended app launch command behind Nginx:

```bash
uwsgi --ini uwsgi.ini
```

## Functional Flow
1. User submits signup request
2. Admin reviews pending requests in `Signup Requests` dashboard
3. Admin approves request and system emails approval notification
4. User logs in with email/password
5. User completes OTP verification from email
6. User views balance, transfers money, and checks history

## Penetration Testing Demonstration Notes

Use these checkpoints in your report/presentation:

1. **Brute force test**
   - Attempt wrong password 5+ times
   - Expected: temporary lockout response

2. **SQL injection test**
   - Try payloads in input fields such as `' OR 1=1 --`
   - Expected: no unauthorized access due to parameterized queries and validation

3. **Weak password discussion**
   - App enforces minimum length and hash storage
   - No plaintext password in DB

4. **Suspicious login tracking**
   - Observe `security.log` and activity logs for abnormal events


