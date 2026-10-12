@echo off
cd /d "%~dp0"
title CYBER SHIELD

:: لو مش شغال كـ Administrator، ارفع الصلاحية وأعد تشغيل نفس السكريبت
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

set "PY=%LOCALAPPDATA%\Python\bin\python.exe"
if not exist "%PY%" set "PY=python"

"%PY%" -c "import flask, flask_cors, scapy.all, psutil" 2>nul
if errorlevel 1 (
    echo [*] تثبيت المتطلبات لأول مرة...
    "%PY%" -m pip install flask flask-cors scapy psutil
)

start "" /min cmd /c "timeout /t 2 /nobreak >nul & start http://localhost:5000"
"%PY%" backend.py
pause
