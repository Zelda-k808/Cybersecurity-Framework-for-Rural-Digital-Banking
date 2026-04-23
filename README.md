# Cybersecurity Framework for Rural Digital Banking

A cybersecurity-driven rural digital banking web application that combines secure system architecture, network monitoring, and penetration testing concepts to enable safe, accessible financial services for underserved communities.

## Project Objective

Build a secure, easy-to-use web banking platform for rural users that is resistant to modern cyber threats while remaining accessible to users with low digital literacy, unstable internet conditions, and high fraud/phishing exposure.

---

## Security Features

### Authentication & Session Management
- **OTP-based 2FA** — email-delivered 6-digit OTP required on every login
- **Bcrypt password hashing** — `Flask-Bcrypt` with cost factor 12
- **Admin approval workflow** — new accounts are pending until an admin approves them
- **Secure session cookies** — `Secure`, `HttpOnly`, `SameSite=Lax` enforced
- **Remember-me cookie** — same protections applied
- **CSRF protection** — all POST forms protected via `Flask-WTF`
- **OTP retry limit** — max 5 OTP attempts before session is cleared
- **Brute-force lockout** — account locked for 15 minutes after 5 failed password attempts

### UI / Client-Side Security
- **Focus-loss blur shield** — full-screen blur overlay activates when the browser tab loses focus, protecting session from screen recording or shoulder surfing
- **Password paste/copy/cut blocked** — JS event listeners prevent clipboard operations on all `password` fields site-wide (including dynamically added fields via `MutationObserver`)
- **No browser autocomplete** on OTP, transfer, and account number fields
- **`user-select: none`** on balance and account number display elements

### Back-Button & Cache Security
- **Global `Cache-Control: no-store`** via `after_request` hook — every response is marked non-cacheable, so pressing Back after logout always hits the server fresh
- **Auth-aware redirects** — `/login` and `/verify-otp` redirect authenticated users to dashboard instead of allowing back-navigation to those pages

### Transfer Security
- **11-digit account number system** — every user gets a unique, auto-generated 11-digit account number on admin approval
- **Strict receiver validation** — transfers require the exact 11-digit receiver account number (regex enforced server-side)
- **Self-transfer prevention** — users cannot transfer money to their own account
- **Atomic balance update** — sender is debited and receiver is credited in the same DB transaction

### Input Validation
- All text fields sanitized with regex — blocks SQL-like patterns (`;`, `'`, `"`, `--`), HTML/JS injection, and control characters
- Parameterized queries used for all database operations (no string interpolation)
- Length limits enforced on all inputs

### Logging & Audit
- **`activity_logs` table** — records all security events (login, failed auth, lockout, logout) with timestamp, IP, user ID
- **`transaction_logs` table** — separate tamper-resistant audit trail for every money transfer (sender, receiver account, amount, note, IP)
- **`security.log`** — file-based log for server-side audit (not committed to git)
- **`transactions.log`** — file-based transaction audit log (not committed to git)

---

## Functional Features

| Feature | Route |
|---|---|
| User registration (pending approval) | `POST /register` |
| Admin approves/views signup requests | `GET/POST /admin/requests` |
| Login with password | `POST /login` |
| OTP verification | `POST /verify-otp` |
| OTP resend | `POST /resend-otp` |
| Dashboard (balance + account number) | `GET /dashboard` |
| Money transfer | `GET/POST /transfer` |
| Transaction history | `GET /history` |
| Admin: security activity logs | `GET /admin/logs` |
| Admin: transaction audit logs | `GET /admin/transaction-logs` |
| Language switcher | `GET /set-language/<lang>` |
| Logout | `GET /logout` |

---

## Multilingual Support

The entire UI supports three languages, switchable at runtime:

| Code | Language | Script |
|---|---|---|
| `en` | English | Latin |
| `hi` | हिन्दी (Hindi) | Devanagari |
| `mr` | मराठी (Marathi) | Devanagari |

Language preference is stored in the session. All 46 UI strings are translated, including navigation, form labels, buttons, headings, and empty-state messages. Language switcher buttons show native script names.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.x, Flask |
| Auth | Flask-Login, Flask-Bcrypt, Flask-WTF |
| Database | SQLite (via `sqlite3`) |
| Templates | Jinja2, HTML5, Vanilla CSS |
| Deployment | uWSGI (Linux), Flask dev server (Windows) |
| Proxy | Werkzeug `ProxyFix` (Nginx-compatible) |

---

## Project Structure

```text
Cybersecurity-Framework-for-Rural-Digital-Banking/
├── app.py                        # Main Flask application
├── requirements.txt
├── uwsgi.ini                     # uWSGI production config
├── .env                          # Local secrets (gitignored)
├── banking.db                    # SQLite database (gitignored)
├── security.log                  # Security event log (gitignored)
├── transactions.log              # Transaction audit log (gitignored)
├── static/
│   └── style.css
├── templates/
│   ├── base.html                 # Layout, blur shield, security JS
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── verify_otp.html
│   ├── dashboard.html
│   ├── transfer.html
│   ├── history.html
│   ├── admin_logs.html
│   ├── admin_requests.html
│   └── admin_transaction_logs.html
└── tests/
    └── test_security.py          # Automated security test suite
```

---

## Setup and Run

### 1. Clone and install

```bash
git clone https://github.com/Zelda-k808/Cybersecurity-Framework-for-Rural-Digital-Banking.git
cd Cybersecurity-Framework-for-Rural-Digital-Banking
pip install -r requirements.txt
```

### 2. Configure environment

Create a `.env` file in the project root (it is gitignored):

```env
SECRET_KEY=your-long-random-secret-key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your-gmail-app-password
SMTP_FROM=your_email@gmail.com
SMTP_USE_TLS=1
```

> **Gmail App Password:** Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords), generate an App Password (requires 2-Step Verification enabled), and use that instead of your regular Gmail password.

### 3. Run (Windows / Development)

```bash
python app.py
```

Then open: [http://127.0.0.1:5000](http://127.0.0.1:5000)

### 4. Run (Linux / Production)

```bash
uwsgi --ini uwsgi.ini
```

---

## Reverse Proxy (Nginx + TLS)

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

Keep `TRUST_REVERSE_PROXY=1` (default) when running behind Nginx.

---

## Functional Flow

```
1. User submits signup request  →  stored as pending
2. Admin reviews /admin/requests  →  approves with one click
3. System assigns unique 11-digit account number  →  sends approval email
4. User logs in with email + password  →  OTP sent to registered email
5. User enters OTP  →  session established
6. User views dashboard (balance + account number)
7. User transfers money using receiver's 11-digit account number
8. Transfer debits sender, credits receiver, logs to transaction_logs
```

---

## Penetration Testing Checkpoints

| Test | Expected Result |
|---|---|
| Wrong password × 5 | Account locked for 15 min |
| Wrong password × 6+ | `Account temporarily locked` message |
| SQL injection in login (`' OR 1=1 --`) | Rejected — parameterized queries |
| XSS/injection in transfer fields | Rejected — regex sanitization |
| Wrong OTP × 5 | OTP session cleared, must log in again |
| Back button after logout | Redirected to login (no-store cache) |
| Back button to OTP after login | Redirected to dashboard |
| Paste into password field | Blocked by JS event listeners |
| Tab away from banking session | Blur shield covers the screen |
| Transfer to non-existent account | `Account not found` error |
| Transfer to own account | `Cannot transfer to yourself` error |
| Transfer more than balance | `Insufficient balance` error |

---

## Automated Tests

```bash
python -m pytest tests/test_security.py -v
```

**6 tests cover:**
- Brute-force lockout enforcement
- SQL injection bypass attempt
- OTP required before dashboard access
- OTP retry limit enforcement
- Transfer input sanitization
- Signup creates pending request (not active user)
