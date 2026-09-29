# UEBA Event Viewer - Quick Start Guide

## Prerequisites
- Python 3.10+
- Windows (for agent)
- Sysmon installed on Windows endpoints

---

## Quick Start

### Option 1: Use Startup Scripts

**Windows:**
1. Double-click `start_server.bat` (starts server)
2. Double-click `start_agent.bat` (starts agent in new window)

**Linux (Server only):**
```bash
chmod +x start_server.sh
./start_server.sh
```

### Option 2: Manual Start

**Server (Linux/Windows):**
```bash
cd server/src
pip install -r ../requirements.txt
python -m server.main
```

**Agent (Windows):**
```powershell
cd agent
pip install -r requirements.txt
python agent.py
```

---

## Access Points

| Component | URL/Port |
|-----------|----------|
| Web Dashboard | http://localhost:8080 |
| Ingest Server | TCP port 9000 |

---

## Configuration Files

| File | Purpose |
|------|---------|
| `server/config/server_config.yaml` | Server settings, SIEM export, UEBA thresholds |
| `agent/config/agent_config.yaml` | Agent settings, channels, flood control |

---

## ELK SIEM Integration

Set environment variables before starting server:
```bash
export ELK_URL="https://your-elk:9200"
export ELK_USERNAME="elastic"
export ES_PASSWORD="your-password"
export ELK_TLS_VERIFY="false"  # For self-signed certs
```

Then enable in `server_config.yaml`:
```yaml
siem:
  enabled: true
```

---

## Troubleshooting

**ModuleNotFoundError:**
```bash
pip install -r requirements.txt
```

**Agent can't connect:**
- Ensure server is running first
- Check `agent_config.yaml` server settings

**No Sysmon events:**
```powershell
Get-Service Sysmon*
```

---

## Architecture

```
[Windows Endpoints]     [Linux Server]
      |                      |
   Agent  ----TCP:9000---> Ingest Server
                             |
                         Normalizer
                             |
                         UEBA Scorer
                             |
                    +--------+--------+
                    |                 |
                 Storage          SIEM Export
                    |                 |
              Web Dashboard    Elasticsearch
```
