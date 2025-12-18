# Maximum Log Capture Guide

This guide provides step-by-step instructions for configuring Windows event logs and the UEBA agent/server for maximum log capture with near real-time forwarding.

## Table of Contents

1. [Windows Event Log Configuration](#windows-event-log-configuration)
2. [Sysmon Configuration](#sysmon-configuration)
3. [Windows Audit Policy](#windows-audit-policy)
4. [Agent Configuration](#agent-configuration)
5. [Server Setup](#server-setup)
6. [Verification](#verification)
7. [Troubleshooting](#troubleshooting)

---

## Windows Event Log Configuration

Configure Windows Event Log sizes to limit local storage while ensuring agent captures all events before they are overwritten.

### PowerShell Commands (Run as Administrator)

```powershell
# Sysmon operational log size (256MB)
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456

# Security log (512MB)
wevtutil sl "Security" /ms:536870912

# System log (256MB)
wevtutil sl "System" /ms:268435456

# Application log (256MB)
wevtutil sl "Application" /ms:268435456

# Optional: PowerShell operational log (256MB)
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456
```

**Note:** `/ms` parameter sets the maximum size in bytes. The agent uses persistent bookmarks to track the last read event ID, so even if Windows logs overwrite, the agent will have already forwarded those events.

### Verify Log Sizes

```powershell
# Check current log sizes
wevtutil gl "Microsoft-Windows-Sysmon/Operational"
wevtutil gl "Security"
wevtutil gl "System"
wevtutil gl "Application"
```

---

## Sysmon Configuration

### Apply Maximum Capture Configuration

1. **Download Sysmon** (if not already installed):
   - https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

2. **Apply the maximum capture configuration**:
   ```powershell
   # Run as Administrator
   sysmon64.exe -c sysmonconfig-max.xml
   # Or if using 32-bit:
   Sysmon.exe -c sysmonconfig-max.xml
   ```

3. **Verify Sysmon is running**:
   ```powershell
   Get-Service Sysmon
   ```

4. **Check Sysmon events**:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10
   ```

### Configuration Details

The `sysmonconfig-max.xml` configuration:
- Logs **all** process creation events (minimal exclusions for Windows telemetry)
- Logs **all** network connections
- Logs **all** file creation/deletion events
- Logs **all** registry modifications
- Logs **all** DNS queries (can be very noisy)
- Logs **all** image loads, driver loads, and other Sysmon events

**Important:** This configuration generates significantly more events than the default export configuration. Ensure your agent has sufficient spool capacity and your server can handle the throughput.

---

## Windows Audit Policy

Enable high-value Security events for comprehensive monitoring.

### PowerShell Commands (Run as Administrator)

```powershell
# Enable Process Creation auditing (success and failure)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable Logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Enable Logoff auditing
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable

# Enable Account Lockout auditing
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Enable File System auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Enable command line logging in Process Creation events
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

### Verify Audit Policy

```powershell
# View current audit policy
auditpol /get /category:*
```

---

## Agent Configuration

### 1. Update Agent Config

Edit `agent/config/agent_config.yaml`:

```yaml
server:
  ip: 192.168.56.101  # Your server IP
  port: 9000

auth:
  enabled: true
  web_port: 8080
  username: "your_agent_username"
  password: "your_agent_password"

# Telemetry settings for reliable log forwarding
telemetry:
  send_interval_seconds: 1      # Flush batches every 1 second
  gui_refresh_seconds: 1        # GUI update interval
  batch_size: 200               # Events per batch
  max_spool_mb: 200             # Maximum spool size
  spool_dir: "%ProgramData%\\UEBAAgent\\spool"
  state_file: "%ProgramData%\\UEBAAgent\\state.json"

# Channel configuration
channels:
  - name: "Microsoft-Windows-Sysmon/Operational"
    enabled: true
  - name: "Security"
    enabled: true
  - name: "System"
    enabled: true
  - name: "Application"
    enabled: true
  - name: "Microsoft-Windows-PowerShell/Operational"
    enabled: false  # Enable if needed
```

### 2. Run Agent

```powershell
# Run as Administrator (required for Security log access)
python agent/run_agent.py
# Or if using compiled EXE:
.\dist\SysmonAgent.exe
```

### 3. Verify Agent Status

The agent will:
- Authenticate with the server
- Start collecting events from all enabled channels
- Forward events in near real-time (1-second batches)
- Spool events to disk if server is unavailable
- Persist bookmarks to resume after restart

**Agent State Files:**
- State: `%ProgramData%\UEBAAgent\state.json` (bookmarks per channel)
- Spool: `%ProgramData%\UEBAAgent\spool\spool_*.ndjson` (durable queue)

---

## Server Setup

### 1. Start Server

```bash
# On Linux server
cd server
python -m src.server.main
# Or using uvicorn directly:
uvicorn src.server.app:app --host 0.0.0.0 --port 8080
```

### 2. Verify Server Status

```bash
# Check if ingest server is listening
netstat -tlnp | grep 9000

# Check server logs
tail -f logs/server.log
```

### 3. Access Web Dashboard

Open browser: `http://<server_ip>:8080`

---

## Verification

### 1. Check Event Counts

**On Server (SQLite):**

```bash
cd server
sqlite3 data/events.db

# Count total events
SELECT COUNT(*) FROM events;

# Count events by source
SELECT source, COUNT(*) FROM events GROUP BY source;

# Count events in last hour
SELECT COUNT(*) FROM events 
WHERE ingested_at > datetime('now', '-1 hour');

# Count events per channel (from raw_json)
SELECT 
  json_extract(raw_json, '$.channel') as channel,
  COUNT(*) as count
FROM events
WHERE raw_json IS NOT NULL
GROUP BY channel;
```

**Expected Results:**
- Events should be increasing rapidly (hundreds to thousands per minute depending on system activity)
- Multiple sources: `sysmon`, `windows_event`
- Events should have recent `ingested_at` timestamps

### 2. Check Session Aggregation

```sql
-- Count session features
SELECT COUNT(*) FROM session_features;

-- View recent sessions
SELECT 
  entity_id,
  entity_type,
  window_start,
  window_end,
  created_at
FROM session_features
ORDER BY created_at DESC
LIMIT 10;
```

**Bootstrap Session Aggregation (if needed):**

```bash
# Using API endpoint
curl -X POST "http://<server_ip>:8080/api/ueba/scheduler/run-sessions?bootstrap_hours=24"

# Or using Python
python -c "
import asyncio
from server.src.server.scheduler.background_tasks import run_session_aggregation
asyncio.run(run_session_aggregation(bootstrap_hours=24))
"
```

**Expected Results:**
- `session_features_count > 0` after bootstrap
- Sessions created for each user/host with activity
- Sessions have hourly windows (`window_start` to `window_end`)

### 3. Check Baseline Stats

```sql
-- Count baseline stats
SELECT COUNT(*) FROM baseline_stats;

-- View recent baselines
SELECT 
  entity_id,
  entity_type,
  feature_name,
  window_end,
  sample_count
FROM baseline_stats
ORDER BY window_end DESC
LIMIT 10;
```

**Expected Results:**
- `baseline_stats_count > 0` after scheduler runs (every 6 hours)
- Baselines for users and hosts
- Feature values stored as JSON strings

### 4. Check Model Training

```sql
-- Count models
SELECT COUNT(*) FROM models;

-- View active models
SELECT 
  model_type,
  entity_id,
  entity_type,
  trained_at,
  training_samples,
  status
FROM models
WHERE status = 'active'
ORDER BY trained_at DESC;
```

**Trigger Model Training (if needed):**

```bash
# Model training runs daily at 2 AM UTC by default
# Or trigger manually via API (if endpoint exists)
```

**Expected Results:**
- `models_count > 0` after training completes
- Model files in `server/data/models/` directory
- Models have `status = 'active'`

### 5. Check Agent Spool Status

**On Windows Agent:**

```powershell
# Check spool directory size
$spoolDir = "$env:ProgramData\UEBAAgent\spool"
Get-ChildItem $spoolDir -Recurse | Measure-Object -Property Length -Sum

# Check state file
Get-Content "$env:ProgramData\UEBAAgent\state.json" | ConvertFrom-Json
```

**Expected Results:**
- Spool should be empty or small if server is reachable
- State file contains bookmarks for each channel
- Spool grows if server is down, drains when server is back up

---

## Troubleshooting

### Agent Not Sending Events

1. **Check authentication:**
   ```powershell
   # Verify credentials in agent_config.yaml
   # Check server logs for authentication errors
   ```

2. **Check network connectivity:**
   ```powershell
   Test-NetConnection -ComputerName <server_ip> -Port 9000
   ```

3. **Check agent logs:**
   - Look for connection errors in console output
   - Check spool directory for queued events

### Events Not Appearing in Database

1. **Check ingest server:**
   ```bash
   # On server
   tail -f logs/server.log | grep INGEST
   ```

2. **Check database path:**
   ```bash
   # Verify database exists
   ls -lh server/data/events.db
   ```

3. **Check event normalization:**
   ```bash
   # Look for normalization errors in logs
   grep -i "normalize" logs/server.log
   ```

### Session Features Not Generated

1. **Check scheduler:**
   ```bash
   # Verify scheduler is running
   grep -i "scheduler" logs/server.log
   ```

2. **Bootstrap manually:**
   ```bash
   # Run bootstrap aggregation
   curl -X POST "http://<server_ip>:8080/api/ueba/scheduler/run-sessions?bootstrap_hours=24"
   ```

3. **Check event timestamps:**
   ```sql
   -- Verify events have proper timestamps
   SELECT MIN(timestamp), MAX(timestamp) FROM events;
   SELECT MIN(ingested_at), MAX(ingested_at) FROM events;
   ```

### High Spool Usage

1. **Check server availability:**
   ```bash
   # On server
   systemctl status ueba-server  # or equivalent
   ```

2. **Increase spool size (if needed):**
   ```yaml
   # In agent_config.yaml
   telemetry:
     max_spool_mb: 500  # Increase from 200
   ```

3. **Drain spool manually:**
   - Restart agent after server is back up
   - Agent will automatically drain spool on next send cycle

### Performance Issues

1. **Reduce batch size:**
   ```yaml
   telemetry:
     batch_size: 100  # Reduce from 200
   ```

2. **Increase send interval:**
   ```yaml
   telemetry:
     send_interval_seconds: 2  # Increase from 1
   ```

3. **Disable noisy channels:**
   ```yaml
   channels:
     - name: "Microsoft-Windows-PowerShell/Operational"
       enabled: false  # Disable if too noisy
   ```

---

## Summary

After completing this guide, you should have:

✅ Windows Event Logs configured with size limits  
✅ Sysmon installed with maximum capture configuration  
✅ Windows Audit Policy enabled for key events  
✅ Agent configured for near real-time forwarding (1-second batches)  
✅ Agent with durable spool queue and bookmark persistence  
✅ Server ingesting events and storing in database  
✅ Session aggregation producing session features  
✅ Baseline stats being computed  
✅ Model training running (if sufficient data)

**Key Metrics to Monitor:**
- Events per minute in database
- Spool backlog size (should be near zero)
- Session features count (should increase hourly)
- Baseline stats count (should increase every 6 hours)
- Model count (should increase daily)

For additional support, check server logs and agent console output for detailed error messages.

