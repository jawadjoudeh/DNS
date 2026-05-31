@echo off
title SecureDNS Guard - Server Starter
echo ===================================================
echo   SecureDNS Guard - Starting Backend Server
echo ===================================================
echo.

cd /d "%~dp0"

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH!
    echo Please install Python 3.9+ from https://www.python.org/
    pause
    exit /b
)

:: Check if virtual environment exists, if not create it
if not exist .venv (
    echo Virtual environment (.venv) not found. Creating it...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo ERROR: Failed to create virtual environment!
        pause
        exit /b
    )
)

:: Activate virtual environment and install requirements
echo Activating virtual environment...
call .venv\Scripts\activate

if not exist .venv\requirements_installed.txt (
    echo Installing dependencies (this may take a minute)...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install dependencies!
        pause
        exit /b
    )
    echo installed > .venv\requirements_installed.txt
)

:: Start Flask app in the background and open browser
echo.
echo Starting Flask Server...
echo The server will run on http://127.0.0.1:5000
echo.
echo Opening default web browser...
start http://127.0.0.1:5000

python app.py
pause
