# Cybersecurity Framework for Rural Digital Banking

A cybersecurity-driven rural digital banking web application that combines secure system architecture, network monitoring, and penetration testing concepts to enable safe, accessible financial services for underserved communities.

## Project Objective

Build a secure, easy-to-use web banking platform for rural users that is resistant to modern cyber threats while remaining accessible to users with low digital literacy, unstable internet conditions, and high fraud/phishing exposure.

---

## Security Features

### Authentication & Session Management
- **OTP-based 2FA** — email-delivered 6-digit OTP required on every login
- **Bcrypt password hashing** — `Flask-Bcrypt`
- **Password policy** — minimum 8 chars, uppercase, lowercase, digit, and special character required
- **Admin approval workflow** — new accounts are pending until an admin approves them
- **Secure session cookies** — `Secure`, `HttpOnly`, `SameSite=Lax` enforced
- **Session inactivity timeout** — auto-logout after **10 minutes** of no activity
- **CSRF protection** — all POST forms protected via `Flask-WTF`
- **OTP retry limit** — max 5 OTP attempts before session is cleared
- **Brute-force lockout** — account locked for 15 minutes after 5 failed password attempts
- **Per-IP rate limiting** — `/register` (5/hour) and `/login` (10/15 min)

### HTTP Security Headers (on every response)
| Header | Value |
|---|---|
| `Cache-Control` | `no-store, no-cache, must-revalidate` |
| `X-Frame-Options` | `DENY` (clickjacking protection) |
| `X-Content-Type-Options` | `nosniff` (MIME-sniffing protection) |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | Restricts scripts, styles, fonts to `'self'` |

### UI / Client-Side Security
- **Focus-loss blur shield** — full-screen blur overlay activates on tab switch
- **Password paste/copy/cut blocked** — prevents clipboard operations on all password fields (+ `MutationObserver` for dynamic fields)
- **`autocomplete="off"`** on OTP, transfer, and account number fields
- **`robots.txt`** — blocks search engines from all sensitive routes

### Transfer Security
- **Transfer confirmation step** — shows summary before executing; re-validates server-side on confirm
- **Daily transfer limit** — ₹50,000 total per user per day
- **11-digit account number system** — auto-generated unique account on approval
- **Self-transfer prevention** — blocked at route level
- **Atomic balance update** — debit sender and credit receiver in the same transaction
- **Minimum transfer amount** — INR 1 minimum enforced

### Input Validation
- All text fields sanitized with regex — blocks SQL-like patterns, HTML/JS injection
- Parameterized queries for all DB operations
- Length limits enforced on all inputs

### Logging & Audit
- **`activity_logs` table** — all security events with timestamp, IP, user ID
- **`transaction_logs` table** — separate tamper-resistant audit trail for every transfer
- **`security.log`** and **`transactions.log`** — file-based logs (gitignored)
- **Admin: security logs** — `/admin/logs`
- **Admin: transaction audit logs** — `/admin/transaction-logs`

---

## Functional Features

| Feature | Route |
|---|---|
| User registration (pending approval) | `POST /register` |
| Admin approves signup requests | `GET/POST /admin/requests` |
| Admin rejects signup requests | `POST /admin/requests/<id>/reject` |
| Admin manage users (activate/deactivate) | `GET /admin/users` |
| Login with password | `POST /login` |
| OTP verification | `POST /verify-otp` |
| OTP resend | `POST /resend-otp` |
| Forgot password (OTP reset flow) | `GET/POST /forgot-password` |
| Change password (logged-in) | `GET/POST /change-password` |
| Dashboard (balance + account number) | `GET /dashboard` |
| Money transfer (step 1 — validate) | `GET/POST /transfer` |
| Money transfer (step 2 — confirm) | `GET/POST /transfer/confirm` |
| Transaction history (paginated) | `GET /history` |
| Admin: security logs (paginated) | `GET /admin/logs` |
| Admin: transaction audit logs (paginated) | `GET /admin/transaction-logs` |
| Language switcher | `GET /set-language/<lang>` |
| Logout | `GET /logout` |

---

## Multilingual Support

| Code | Language | Script |
|---|---|---|
| `en` | English | Latin |
| `hi` | हिन्दी (Hindi) | Devanagari |
| `mr` | मराठी (Marathi) | Devanagari |

All 50+ UI strings translated including navigation, form labels, buttons, headings, confirmation messages, and empty-state messages.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.x, Flask 3.1.3 |
| Auth | Flask-Login 0.6.3, Flask-Bcrypt 1.0.1, Flask-WTF 1.2.2 |
| Database | SQLite (via `sqlite3`) |
| Templates | Jinja2, HTML5, Vanilla CSS |
| Deployment | uWSGI (Linux production), Flask dev server (Windows) |
| Proxy | Werkzeug `ProxyFix` (Nginx-compatible) |

---

## Project Structure

```text
Cybersecurity-Framework-for-Rural-Digital-Banking/
├── app.py                          # Main Flask application
├── requirements.txt                # Pinned exact versions
├── uwsgi.ini                       # uWSGI production config
├── .env                            # Local secrets (gitignored)
├── run_dev.bat                     # Windows dev launcher (gitignored)
├── banking.db                      # SQLite database (gitignored)
├── security.log                    # Security event log (gitignored)
├── transactions.log                # Transaction audit log (gitignored)
├── static/
│   ├── style.css
│   └── robots.txt
├── templates/
│   ├── base.html                   # Layout, blur shield, security JS
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── verify_otp.html
│   ├── dashboard.html
│   ├── transfer.html
│   ├── transfer_confirm.html       # Step 2 confirmation page
│   ├── history.html                # Paginated
│   ├── change_password.html
│   ├── forgot_password.html
│   ├── verify_reset_otp.html
│   ├── reset_password.html
│   ├── admin_logs.html             # Paginated
│   ├── admin_requests.html         # Approve + Reject buttons
│   ├── admin_transaction_logs.html # Paginated
│   └── admin_users.html            # Activate / Deactivate
└── tests/
    └── test_security.py            # 11 automated pen-test cases
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

Create a `.env` file in the project root (gitignored):

```env
SECRET_KEY=your-long-random-secret-key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your-gmail-app-password
SMTP_FROM=your_email@gmail.com
SMTP_USE_TLS=1
```

> **Gmail App Password:** Go to [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords), generate an App Password (requires 2-Step Verification), and use that as `SMTP_PASSWORD`.

### 3. Run (Windows / Development)

```bash
python app.py
```
Or double-click `run_dev.bat` (after filling in `SMTP_PASSWORD`).

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

---

## Functional Flow

```
1. User submits signup request  →  stored as pending
2. Admin reviews /admin/requests  →  Approve or Reject
3. On approval: unique 11-digit account number assigned, approval email sent
4. On rejection: rejection email sent to user
5. User logs in with email + password  →  OTP sent to email
6. User enters OTP  →  session established (10-min inactivity timeout)
7. User views dashboard (balance + account number)
8. User fills transfer form  →  confirmation page shown
9. User confirms  →  atomic debit/credit executed, daily limit checked, audit logged
10. Admin can deactivate compromised accounts via /admin/users
```

---

## Automated Security Tests

```bash
python -m pytest tests/test_security.py -v
```

**11 tests covering:**

| Test | Attack / Scenario |
|---|---|
| `test_bruteforce_lockout_after_multiple_failures` | Brute-force login |
| `test_csrf_protection_is_active_on_all_forms` | CSRF middleware presence |
| `test_customer_cannot_access_admin_routes` | Privilege escalation |
| `test_no_store_cache_headers_on_authenticated_responses` | Back-button cache attack |
| `test_otp_required_before_dashboard_access` | OTP bypass |
| `test_otp_retry_limit_enforced` | OTP brute-force |
| `test_signup_creates_pending_request_not_active_user` | Instant account activation |
| `test_sql_injection_payload_cannot_bypass_login` | SQL injection |
| `test_transfer_input_sanitization_blocks_injection_patterns` | Input injection in transfer |
| `test_transfer_to_own_account_is_rejected` | Self-transfer |
| `test_transfer_with_insufficient_balance_is_rejected` | Overdraft / negative balance |
| `test_rate_limit_register_blocks_flooding` | Mass signup flooding |
| `test_rate_limit_login_blocks_flooding` | Mass login flooding |
| `test_daily_transfer_limit_enforced` | Daily cap bypass |
| `test_change_password_requires_current_password` | Password change without auth |
| `test_forgot_password_flow_sends_otp` | Password reset flow |
| `test_admin_can_toggle_user_active` | Account deactivation bypass |

---

## Penetration Testing Checkpoints

| Test | Expected Result |
|---|---|
| Wrong password × 5 | Account locked for 15 min |
| SQL injection in login `' OR 1=1 --` | Rejected — parameterized queries |
| XSS/injection in transfer fields | Rejected — regex sanitization |
| Wrong OTP × 5 | Session cleared |
| Back button after logout | Redirected to login (no-store cache) |
| Paste into password field | Blocked by JS |
| Tab away from session | Blur shield covers screen |
| Transfer to own account | Rejected |
| Transfer > balance | Rejected |
| Customer visits `/admin/*` | Unauthorized — redirected |
| Page in iframe | Blocked — `X-Frame-Options: DENY` |
| Idle for 10+ minutes | Auto-logged out |
| Weak password (no special char) | Registration rejected |
| Daily transfer > ₹50,000 | Rejected |
| Mass registration from same IP | Rate-limited |
| Admin deactivate user | Account locked, login blocked |
