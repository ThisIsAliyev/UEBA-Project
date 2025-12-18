# UEBA Maximum Telemetry Test Plan

## Overview

This test plan validates the end-to-end flow of maximum telemetry collection, normalization, storage, and alerting in the UEBA system.

**Test Environment:**
- Windows 10/11 machine with Administrator privileges
- Sysmon installed and configured
- Agent running and connected to server
- Server running and accessible

---

## Prerequisites

1. ✅ Windows audit policy enabled (`agent/setup_windows_audit.ps1`)
2. ✅ Sysmon configured with `sysmonconfig-max.xml`
3. ✅ Agent configured and running
4. ✅ Server running and accessible
5. ✅ Database accessible for verification

---

## Test Cases

### TC-1: Lock/Unlock Events (CRITICAL)

**Objective:** Verify that workstation lock/unlock events (4800/4801) are captured, normalized, and stored.

**Steps:**
1. Ensure agent is running and connected to server
2. Lock workstation (Win+L or Ctrl+Alt+Del → Lock)
3. Wait 5 seconds
4. Unlock workstation (enter password/PIN)
5. Wait 5 seconds

**Verification:**
```sql
-- Check events in database
SELECT timestamp, host, user, event_id, action_type, channel, message 
FROM events 
WHERE event_id IN (4800, 4801) 
ORDER BY timestamp DESC 
LIMIT 10;
```

**Expected Results:**
- ✅ Event 4800 (lock) appears in database with `action_type='lock'`
- ✅ Event 4801 (unlock) appears in database with `action_type='unlock'`
- ✅ Events visible in dashboard UI under Events page
- ✅ Events have correct user, host, timestamp
- ✅ Channel = "Security"
- ✅ Provider = "Microsoft-Windows-Security-Auditing"

**Pass Criteria:** Both events captured and visible in DB/UI within 10 seconds

---

### TC-2: PowerShell Operational Events

**Objective:** Verify PowerShell script execution events are captured.

**Steps:**
1. Open PowerShell as Administrator
2. Run: `Get-Process | Select-Object -First 5`
3. Run: `Write-Host "Test script block"`
4. Wait 5 seconds

**Verification:**
```sql
-- Check PowerShell events
SELECT timestamp, host, user, event_id, action_type, channel, message 
FROM events 
WHERE channel LIKE '%PowerShell%' 
ORDER BY timestamp DESC 
LIMIT 10;
```

**Expected Results:**
- ✅ PowerShell Operational events appear in database
- ✅ `action_type` includes 'ps_scriptblock' or 'ps_activity'
- ✅ Channel = "Microsoft-Windows-PowerShell/Operational"
- ✅ Events visible in dashboard

**Pass Criteria:** At least one PowerShell event captured within 10 seconds

---

### TC-3: Task Scheduler Events

**Objective:** Verify scheduled task creation events are captured.

**Steps:**
1. Open Task Scheduler (taskschd.msc)
2. Create a new task:
   - Name: "UEBA Test Task"
   - Trigger: One time, 1 minute from now
   - Action: Start a program (notepad.exe)
3. Save the task
4. Wait 5 seconds

**Verification:**
```sql
-- Check Task Scheduler events
SELECT timestamp, host, user, event_id, action_type, channel, message 
FROM events 
WHERE channel LIKE '%TaskScheduler%' 
ORDER BY timestamp DESC 
LIMIT 10;
```

**Expected Results:**
- ✅ Task Scheduler events appear in database
- ✅ `action_type` includes 'task_created' or 'task_updated'
- ✅ Channel = "Microsoft-Windows-TaskScheduler/Operational"
- ✅ Events visible in dashboard

**Pass Criteria:** Task creation event captured within 10 seconds

---

### TC-4: File Download / BITS Events

**Objective:** Verify file creation and BITS download events are captured.

**Steps:**
1. Download a file using browser (e.g., download a small text file)
2. Or trigger BITS transfer:
   ```powershell
   Start-BitsTransfer -Source "https://www.example.com/file.txt" -Destination "C:\temp\test.txt"
   ```
3. Wait 10 seconds

**Verification:**
```sql
-- Check file and BITS events
SELECT timestamp, host, user, event_id, action_type, channel, target_filename 
FROM events 
WHERE (action_type LIKE '%file%' OR channel LIKE '%Bits%')
  AND timestamp > datetime('now', '-1 minute')
ORDER BY timestamp DESC;
```

**Expected Results:**
- ✅ File creation events (Sysmon event 11) appear
- ✅ BITS events appear if BITS channel enabled
- ✅ `target_filename` populated
- ✅ Events visible in dashboard

**Pass Criteria:** File creation event captured (BITS optional)

---

### TC-5: WMI Activity Events

**Objective:** Verify WMI execution events are captured.

**Steps:**
1. Run PowerShell:
   ```powershell
   Get-WmiObject -Class Win32_Process | Select-Object -First 3
   ```
2. Wait 5 seconds

**Verification:**
```sql
-- Check WMI events
SELECT timestamp, host, user, event_id, action_type, channel, message 
FROM events 
WHERE channel LIKE '%WMI%' 
ORDER BY timestamp DESC 
LIMIT 10;
```

**Expected Results:**
- ✅ WMI Activity events appear in database
- ✅ `action_type` includes 'wmi_exec' or 'wmi_activity'
- ✅ Channel = "Microsoft-Windows-WMI-Activity/Operational"
- ✅ Events visible in dashboard

**Pass Criteria:** WMI event captured within 10 seconds

---

### TC-6: RDP Session Events

**Objective:** Verify RDP connection events are captured.

**Steps:**
1. If RDP is enabled, connect via RDP (or simulate)
2. Or check existing RDP events in Event Viewer
3. Wait 5 seconds

**Verification:**
```sql
-- Check RDP events
SELECT timestamp, host, user, event_id, action_type, channel, message 
FROM events 
WHERE channel LIKE '%TerminalServices%' OR action_type LIKE '%rdp%'
ORDER BY timestamp DESC 
LIMIT 10;
```

**Expected Results:**
- ✅ RDP session events appear in database (if RDP used)
- ✅ `action_type` includes 'rdp_connect' or 'rdp_session'
- ✅ Channel includes "TerminalServices"
- ✅ Events visible in dashboard

**Pass Criteria:** RDP events captured if RDP is used (optional test)

---

### TC-7: Multi-Channel Collection

**Objective:** Verify multiple channels are being collected simultaneously.

**Steps:**
1. Perform actions from TC-1 through TC-5
2. Wait 30 seconds for all events to be collected

**Verification:**
```sql
-- Count events by channel
SELECT channel, COUNT(*) as event_count 
FROM events 
WHERE timestamp > datetime('now', '-5 minutes')
GROUP BY channel 
ORDER BY event_count DESC;
```

**Expected Results:**
- ✅ Events from multiple channels present:
  - Security (lock/unlock)
  - Microsoft-Windows-Sysmon/Operational
  - Microsoft-Windows-PowerShell/Operational
  - Microsoft-Windows-TaskScheduler/Operational
  - Microsoft-Windows-WMI-Activity/Operational
  - System
- ✅ Each channel has events

**Pass Criteria:** At least 5 different channels have events

---

### TC-8: Normalization and Action Types

**Objective:** Verify events are properly normalized with action_type.

**Steps:**
1. Review events from previous tests

**Verification:**
```sql
-- Check action_type distribution
SELECT action_type, COUNT(*) as count 
FROM events 
WHERE timestamp > datetime('now', '-5 minutes')
  AND action_type IS NOT NULL
GROUP BY action_type 
ORDER BY count DESC;
```

**Expected Results:**
- ✅ Various action_type values present:
  - lock, unlock
  - logon, logoff
  - process_create
  - file_create
  - ps_scriptblock or ps_activity
  - wmi_exec or wmi_activity
  - task_created
- ✅ All events have proper normalization

**Pass Criteria:** Multiple action_type values present and correctly assigned

---

### TC-9: Risk Scoring and Alerts

**Objective:** Verify risk engine generates scores and alerts for suspicious activity.

**Steps:**
1. Perform suspicious activity:
   - Lock/unlock at unusual hour (e.g., 2 AM)
   - Run suspicious PowerShell command
   - Create scheduled task with unusual path
2. Wait 30 seconds for risk scoring

**Verification:**
```sql
-- Check risk scores
SELECT timestamp, host, user, event_id, action_type, risk_score, risk_level 
FROM events 
WHERE timestamp > datetime('now', '-5 minutes')
  AND risk_score IS NOT NULL
ORDER BY risk_score DESC 
LIMIT 10;

-- Check alerts
SELECT user, host, severity, reasons_json, first_seen, last_seen 
FROM alerts 
WHERE first_seen > datetime('now', '-5 minutes')
ORDER BY first_seen DESC;
```

**Expected Results:**
- ✅ Events have risk_score populated
- ✅ High-risk events have risk_level = 'high' or 'medium'
- ✅ Alerts generated for suspicious activity
- ✅ Alerts have reasons_json explaining why triggered
- ✅ Alerts visible in dashboard

**Pass Criteria:** Risk scores assigned and at least one alert generated

---

### TC-10: Dashboard UI

**Objective:** Verify dashboard displays events and alerts correctly.

**Steps:**
1. Open dashboard in browser: `http://localhost:8080`
2. Navigate to Events page
3. Navigate to Alerts page
4. Navigate to Overview page

**Verification:**
- ✅ Events page shows recent events with filters
- ✅ Lock/unlock events visible and highlighted
- ✅ PowerShell events visible
- ✅ Alerts page shows generated alerts
- ✅ Alert detail shows reasons and evidence
- ✅ Overview shows user baselines and statistics

**Pass Criteria:** All pages load and display data correctly

---

### TC-11: Agent Reliability (Spool Queue)

**Objective:** Verify agent handles server unavailability gracefully.

**Steps:**
1. Stop server
2. Perform lock/unlock action
3. Wait 30 seconds
4. Start server
5. Wait 30 seconds

**Verification:**
```sql
-- Check if events eventually arrive
SELECT COUNT(*) 
FROM events 
WHERE event_id IN (4800, 4801) 
  AND timestamp > datetime('now', '-10 minutes');
```

**Expected Results:**
- ✅ Agent continues collecting events when server is down
- ✅ Events are spooled to disk
- ✅ Events are sent when server comes back online
- ✅ No data loss

**Pass Criteria:** Events eventually appear in database after server restart

---

## Test Execution Log

| Test Case | Status | Notes | Date |
|-----------|--------|-------|------|
| TC-1: Lock/Unlock | ⬜ Pending | | |
| TC-2: PowerShell | ⬜ Pending | | |
| TC-3: Task Scheduler | ⬜ Pending | | |
| TC-4: File/BITS | ⬜ Pending | | |
| TC-5: WMI | ⬜ Pending | | |
| TC-6: RDP | ⬜ Pending | Optional | |
| TC-7: Multi-Channel | ⬜ Pending | | |
| TC-8: Normalization | ⬜ Pending | | |
| TC-9: Risk Scoring | ⬜ Pending | | |
| TC-10: Dashboard | ⬜ Pending | | |
| TC-11: Agent Reliability | ⬜ Pending | | |

---

## Quick Verification Commands

### PowerShell (on Windows Agent)
```powershell
# Check if lock/unlock events are being generated
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4800 or EventID=4801)]]" | Select-Object -First 5

# Check PowerShell events
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Select-Object -First 5

# Check Task Scheduler events
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" | Select-Object -First 5
```

### SQLite (on Server)
```sql
-- Quick event count by channel
SELECT channel, COUNT(*) as count 
FROM events 
WHERE timestamp > datetime('now', '-1 hour')
GROUP BY channel;

-- Recent lock/unlock events
SELECT * FROM events 
WHERE event_id IN (4800, 4801) 
ORDER BY timestamp DESC 
LIMIT 5;

-- Recent alerts
SELECT * FROM alerts 
ORDER BY first_seen DESC 
LIMIT 5;
```

---

## Known Issues / Limitations

1. **AppLocker Channels**: May not exist on all Windows versions - agent handles gracefully
2. **BITS Events**: May require specific conditions to trigger
3. **RDP Events**: Only captured if RDP is actually used
4. **Defender Events**: Only captured if Windows Defender is active

---

## Test Environment Setup

### Windows Agent
```powershell
# 1. Enable audit policy
.\agent\setup_windows_audit.ps1

# 2. Apply Sysmon config
sysmon64.exe -c sysmonconfig-max.xml

# 3. Configure agent
# Edit agent/config/agent_config.yaml

# 4. Run agent
python agent/run_agent.py
```

### Server
```bash
# 1. Install dependencies
pip install -r server/requirements.txt

# 2. Configure server
# Edit server/config/server_config.yaml

# 3. Run server
python server/src/server/main.py
```

---

## Success Criteria

**Minimum Pass:** TC-1, TC-2, TC-7, TC-8, TC-10 must pass

**Full Pass:** All test cases pass (TC-6 optional)

---

*Last Updated: 2024-01-XX*

