#!/bin/bash
echo "========================================"
echo "  UEBA Server Startup Script (Linux)"
echo "========================================"
echo

cd "$(dirname "$0")/server/src"

echo "Installing dependencies..."
pip3 install -r ../requirements.txt -q

echo
echo "Starting UEBA Server..."
echo "  Web UI: http://localhost:8080"
echo "  Ingest: localhost:9000"
echo

python3 -m server.main
