@echo off
echo ========================================
echo   UEBA Agent Startup Script
echo ========================================
echo.

cd /d "%~dp0agent"

echo Installing dependencies...
pip install -r requirements.txt -q

echo.
echo Starting UEBA Agent...
echo   Server: 127.0.0.1:9000
echo.

python agent.py

pause
