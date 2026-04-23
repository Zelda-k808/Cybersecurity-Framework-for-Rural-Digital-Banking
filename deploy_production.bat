@echo off
setlocal

echo ==========================================
echo Preparing Production Environment
echo ==========================================

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found in PATH.
    exit /b 1
)

echo.
echo [1/3] Installing required production dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install requirements.
    exit /b 1
)

echo.
echo [2/3] Removing Windows dev fallback server (waitress)...
python -m pip uninstall -y waitress >nul 2>nul

echo.
echo [3/3] Production dependency preparation complete.
echo NOTE: Flask framework is REQUIRED by this project.
echo       uWSGI serves the Flask app in production.
echo.
echo Linux production launch command:
echo   uwsgi --ini uwsgi.ini

exit /b 0
