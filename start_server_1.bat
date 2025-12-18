@echo off
echo ========================================
echo   UEBA Server Startup Script
echo ========================================
echo.

cd /d "%~dp0server\src"

echo Installing dependencies...
pip install -r ..\requirements.txt -q

REM ========================================
REM SIEM/Elasticsearch Configuration
REM ========================================
set ES_USERNAME=elastic
set ES_PASSWORD=5y1TPgd1u16uJIGMm2nL
set ELK_TLS_VERIFY=false

echo.
echo Starting UEBA Server...
echo   Web UI: http://localhost:8080
echo   Ingest: localhost:9000
echo   SIEM:   https://10.10.4.151:9200
echo.

python -m server.main

pause
