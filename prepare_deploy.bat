@echo off
REM ============================================================
REM  prepare_deploy.bat
REM  Reverts app.py to production mode (uWSGI only).
REM  Run this BEFORE deploying to a Linux/uWSGI server.
REM  DO NOT run this on Windows — the app won't start after.
REM ============================================================

echo [*] Reverting app.py to production (uWSGI) mode...

REM Use Python to do the replacement safely
python -c ^
"import re, sys; ^
f = open('app.py', 'r'); content = f.read(); f.close(); ^
old = 'if __name__ == \"__main__\":\n    # uWSGI is Linux-only; use Flask dev server on Windows\n    app.config[\"SESSION_COOKIE_SECURE\"] = False\n    app.config[\"REMEMBER_COOKIE_SECURE\"] = False\n    app.run(debug=True, host=\"127.0.0.1\", port=5000)'; ^
new = 'if __name__ == \"__main__\":\n    raise SystemExit(\"Run this application with uWSGI: \`uwsgi --ini uwsgi.ini\`\")'; ^
if old not in content: print('[!] Block not found - already in production mode or manually changed.'); sys.exit(1); ^
content = content.replace(old, new); ^
f = open('app.py', 'w'); f.write(content); f.close(); ^
print('[+] Done. app.py is now in production (uWSGI) mode.')"

if %ERRORLEVEL% NEQ 0 (
    echo [!] Something went wrong. Check app.py manually.
    pause
    exit /b 1
)

echo.
echo [+] app.py is ready for deployment.
echo [+] Deploy to your Linux server and run: uwsgi --ini uwsgi.ini
echo.
pause
