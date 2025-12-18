# Troubleshooting: Events Not Appearing from Windows Agent

## Quick Checks

### 1. Verify Server is Running
```bash
# Check if server is listening on port 9000
netstat -tuln | grep 9000
# or
ss -tuln | grep 9000
```

### 2. Check Server Logs
```bash
tail -f logs/server.log
```

Look for:
- "Ingest server listening on..." 
- "Client connected from..."
- Any error messages

### 3. Test Ingest Server Directly
```bash
cd server
python test_ingest.py
```

This sends a test event to verify the ingest server is working.

### 4. Check Ingest Server Status
```bash
curl http://localhost:8080/api/ingest/status
```

Should return:
```json
{
  "running": true,
  "host": "0.0.0.0",
  "port": 9000,
  "event_count": 0,
  "alert_count": 0,
  "error_count": 0,
  "connected_clients": 0
}
```

## Common Issues

### Issue 1: SIEM Export Blocking (Fixed)
**Symptom**: Server starts but no events appear
**Solution**: SIEM export errors are now non-blocking. If Elasticsearch is unreachable, events will still be stored.

**To temporarily disable SIEM export:**
Edit `config/server_config.yaml`:
```yaml
siem:
  enabled: false  # Change to false
```

### Issue 2: Agent Not Connecting
**Symptom**: No "Client connected" messages in logs

**Check:**
1. Agent IP/port configuration
2. Firewall rules (port 9000 must be open)
3. Network connectivity: `ping <server-ip>`

**Agent Configuration:**
- Server IP: Should be the UEBA server IP
- Port: 9000 (default)
- Agent must send auth message first: `{"agent_token": "..."}`

### Issue 3: Authentication Failing
**Symptom**: "Client failed authentication" in logs

**Note**: Authentication is required. All agents must provide a valid token.

If you see authentication errors, check:
- Agent is sending auth message as first line
- Auth message is valid JSON: `{"agent_token": "..."}`
- Agent token is valid and agent is approved in the system

### Issue 4: Events Not Normalizing
**Symptom**: "Failed to normalize event" in logs

**Check:**
- Event format matches expected envelope:
  ```json
  {"source": "sysmon", "event": {...}}
  ```
- Or legacy format:
  ```json
  {"Id": 1, "TimeCreated": "...", ...}
  ```

### Issue 5: Database Issues
**Symptom**: Events received but not stored

**Check:**
- Database file exists: `data/events.db`
- Database permissions
- Disk space

**Verify events in database:**
```bash
sqlite3 data/events.db "SELECT COUNT(*) FROM events;"
sqlite3 data/events.db "SELECT * FROM events ORDER BY id DESC LIMIT 5;"
```

## Debugging Steps

### Step 1: Verify Server Started Correctly
```bash
# Check startup logs
grep "SIEM exporter" logs/server.log
grep "Ingest server" logs/server.log
```

Expected output:
```
SIEM exporter started
Starting ingest server on port 9000...
Ingest server listening on ('0.0.0.0', 9000) (TCP)
```

### Step 2: Test Network Connectivity
From Windows agent machine:
```powershell
Test-NetConnection -ComputerName <server-ip> -Port 9000
```

### Step 3: Monitor Real-Time Events
```bash
# Watch for new events
tail -f logs/server.log | grep -E "(Client connected|Processed|event)"
```

### Step 4: Check API Endpoints
```bash
# Get latest events
curl http://localhost:8080/api/events?limit=5

# Get ingest stats
curl http://localhost:8080/api/ingest/status
```

### Step 5: Test with Manual Event
Use the test script:
```bash
cd server
python test_ingest.py
```

Then check:
```bash
# Check if event appeared
curl http://localhost:8080/api/events?limit=1
```

## SIEM Export Issues

If SIEM export is enabled but Elasticsearch is unreachable:

1. **Check Elasticsearch connectivity:**
   ```bash
   curl http://10.10.4.151:9200
   ```

2. **Check SIEM export logs:**
   ```bash
   grep "SIEM" logs/server.log
   ```

3. **Temporarily disable SIEM:**
   Edit `config/server_config.yaml`:
   ```yaml
   siem:
     enabled: false
   ```
   Restart server.

4. **SIEM export errors are non-blocking** - events will still be stored even if SIEM export fails.

## Agent-Side Checks

### Windows Agent Configuration
Check `agent/config/agent_config.yaml`:
```yaml
server:
  ip: "<server-ip>"  # Must be correct
  port: 9000
```

### Agent Logs
Check agent console output for:
- Connection errors
- "Failed to send events" messages
- Network errors

### Test Agent Connection
From Windows machine:
```powershell
$tcpClient = New-Object System.Net.Sockets.TcpClient
$tcpClient.Connect("<server-ip>", 9000)
if ($tcpClient.Connected) {
    Write-Host "Connection successful"
    $tcpClient.Close()
} else {
    Write-Host "Connection failed"
}
```

## Still Not Working?

1. **Enable debug logging:**
   Edit `config/server_config.yaml`:
   ```yaml
   logging:
     level: "DEBUG"
   ```

2. **Check all logs:**
   ```bash
   tail -f logs/server.log
   ```

3. **Verify database:**
   ```bash
   sqlite3 data/events.db ".tables"
   sqlite3 data/events.db "SELECT COUNT(*) FROM events;"
   ```

4. **Restart server:**
   ```bash
   # Stop server (Ctrl+C)
   # Start again
   python -m src.server.main
   ```

## Expected Behavior

When working correctly, you should see:
1. Server starts: "Ingest server listening on..."
2. Agent connects: "Client connected from..."
3. Events processed: "Processed X events..."
4. Events in database: Query `/api/events` returns data
5. Events in dashboard: View at `http://<server-ip>:8080/events`
