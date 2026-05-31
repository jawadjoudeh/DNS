@echo off
title SecureDNS Guard - DNS Proxy Client
echo ===================================================
echo   SecureDNS Guard - Starting DNS Proxy Client
echo ===================================================
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath '%0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

if not exist dns_proxy.py (
    echo ERROR: dns_proxy.py was not found in this folder!
    echo.
    echo Please follow these steps to get it:
    echo 1. Double-click "Start_Server.bat" to start the system.
    echo 2. Go to the "Profile" page inside the dashboard.
    echo 3. Click "Download dns_proxy.py" and save it in this directory.
    echo.
    pause
    exit /b
)

echo Starting DNS Proxy Client (UDP Port 53)...
echo (Make sure the backend server is running first!)
echo.
python dns_proxy.py
pause
