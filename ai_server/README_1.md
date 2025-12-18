# UEBA AI Server

LLM-based security event analysis microservice for the UEBA platform.

## Overview

This service provides AI-powered analysis of security events using a local Ollama LLM instance. It receives events from the Web Server, analyzes them for potential threats, and returns structured verdicts.

## Architecture

```
Web Server (192.168.213.136)
    │
    │ POST /api/v1/analyze
    │ Header: X-API-Key
    ▼
AI Server (192.168.213.138:8000)
    │
    │ Internal call
    ▼
Ollama (127.0.0.1:11434)
    │
    ▼
LLM Model (llama3.2:3b)
```

## Requirements

- Ubuntu Server 22.04/24.04 LTS
- Python 3.11+
- Ollama with a suitable model (llama3.2:3b recommended)

## Installation

### 1. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### 2. Configure Ollama for localhost only

```bash
sudo systemctl edit ollama
```

Add:
```ini
[Service]
Environment="OLLAMA_HOST=127.0.0.1:11434"
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

### 3. Pull the model

```bash
ollama pull llama3.2:3b
```

### 4. Set up AI Server

```bash
cd /opt/ai_server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 5. Configure environment

```bash
cp .env.example .env
# Edit .env with your API key and settings
chmod 600 .env
```

### 6. Configure firewall

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 192.168.213.136 to any port 8000 proto tcp comment "Web Server"
sudo ufw allow from 192.168.213.0/24 to any port 22 proto tcp comment "SSH"
sudo ufw enable
```

### 7. Run the server

Development:
```bash
source venv/bin/activate
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
```

Production (systemd):
```bash
sudo cp ai-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ai-server
sudo systemctl start ai-server
```

## API Endpoints

### Health Check
```
GET /health
```
No authentication required. Returns server and Ollama status.

### Analyze Events
```
POST /api/v1/analyze
Header: X-API-Key: <your-api-key>
Content-Type: application/json
```

Request body:
```json
{
  "request_id": "evt_12345",
  "events": [
    {
      "process_name": "powershell.exe",
      "command_line": "powershell -enc SGVsbG8=",
      "parent_process_name": "winword.exe",
      "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    }
  ],
  "context": {
    "user": "john.doe",
    "host": "WORKSTATION-1"
  },
  "rule_score": 55
}
```

Response:
```json
{
  "request_id": "evt_12345",
  "label": "SUSPICIOUS",
  "score": 65,
  "confidence": 0.75,
  "reason": "Encoded PowerShell spawned by Office application",
  "comment": "The event shows winword.exe spawning powershell.exe with base64-encoded command...",
  "source": "ai_server",
  "error": null
}
```

## Response Schema

All enrichment sources (AI Server, n8n workflows) use this canonical schema:

| Field | Type | Description |
|-------|------|-------------|
| request_id | string | Correlation ID from Web Server |
| label | enum | MALICIOUS, SUSPICIOUS, or BENIGN |
| score | int | Risk score 0-100 |
| confidence | float | Confidence level 0.0-1.0 |
| reason | string | Short explanation (max 200 chars) |
| comment | string | Detailed explanation (max 1000 chars) |
| source | string | Service that produced this response |
| sources | object | Detailed results (for aggregated responses) |
| error | string | Error message if analysis failed |

## Security

- API key authentication via X-API-Key header
- IP whitelist restricts access to Web Server only
- Ollama bound to localhost only
- UFW firewall blocks all except authorized traffic
