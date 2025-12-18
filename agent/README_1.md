# Windows Agent

> **📖 For full project documentation, see the [main README](../README.md) in the repository root.**

A lightweight Windows agent that collects Sysmon and Windows Security events and forwards them to the UEBA Web Server for analysis.

---

## Features

- **Maximum Telemetry Collection**: Collects events from 15+ Windows Event Log channels including:
  - Sysmon (process, file, network, registry, DNS, WMI, etc.)
  - Security (logon, logoff, lock/unlock, account management, privilege use)
  - PowerShell (script blocks, module loads, runspaces)
  - WMI Activity (WMI execution, filters, consumers)
  - Task Scheduler (task creation, execution, deletion)
  - Windows Defender (alerts, config changes)
  - Windows Firewall (rule changes, connection filters)
  - RDP Sessions (local and remote connections)
  - BITS (downloads)
  - AppLocker (execution blocks)
  - Code Integrity (blocked code execution)
  - System (USB/device events, service events, etc.)
- **Lock/Unlock Detection**: Captures workstation lock (4800) and unlock (4801) events for UEBA analysis
- **Efficient Forwarding**: Streams events as newline-delimited JSON (NDJSON) over TCP with batching
- **Durable Spool Queue**: Prevents data loss during network/server downtime
- **State Persistence**: Bookmarks per channel to resume from last position
- **Simple Configuration**: Uses YAML file to configure channels and server endpoint
- **Standalone Executable**: Pre-built with PyInstaller for easy deployment
- **GUI for Configuration**: Tkinter GUI for easy configuration and real-time statistics

---

## Quick Start

1.  **Prerequisites**: 
    - Ensure Sysmon is installed on the Windows machine
    - Run Windows as Administrator
2.  **Enable Windows Auditing** (one-time setup):
    ```powershell
    # Run as Administrator
    .\setup_windows_audit.ps1
    ```
    This enables comprehensive auditing including Lock/Unlock events (4800/4801).
3.  **Apply Maximum Sysmon Configuration**:
    ```powershell
    # Run as Administrator
    sysmon64.exe -c ..\sysmonconfig-max.xml
    ```
4.  **Run Agent**: Execute `dist/SysmonAgent.exe` as an Administrator.
5.  **Configure**: In the GUI, enter the IP address of the Web Server (e.g., `192.168.213.136`) and port `9000`.
6.  **Start**: Click "Start" to begin forwarding events.

---

## Architecture

The agent performs two main tasks:

1.  **Event Polling**: A background thread continuously polls the Sysmon and Security event logs for new records.
2.  **TCP Forwarding**: Each new event is wrapped in a JSON envelope (`{"source": "sysmon", "event": {...}}`) and sent over a TCP stream to the Web Server's ingest port.

---

## Configuration

Settings are stored in `config/agent_config.yaml`:

```yaml
server:
  ip: "192.168.213.136"  # IP of the UEBA Web Server
  port: 9000              # Ingest port

auth:
  enabled: true
  web_port: 8080
  username: "your_agent_username"
  password: "your_agent_password"

# Telemetry settings for reliable log forwarding
telemetry:
  send_interval_seconds: 1      # Flush batches every 1 second (near real-time)
  gui_refresh_seconds: 1         # GUI update interval
  batch_size: 200               # Events per batch
  max_spool_mb: 200             # Maximum spool size for durability
  spool_dir: "%ProgramData%\\UEBAAgent\\spool"
  state_file: "%ProgramData%\\UEBAAgent\\state.json"

# Channel configuration (enable/disable specific Windows Event Log channels)
# Maximum telemetry collection for UEBA detection
channels:
  # Core channels (must-collect for UEBA)
  - name: "Microsoft-Windows-Sysmon/Operational"
    enabled: true
    source_name: "SYSMON"
  - name: "Security"
    enabled: true
    source_name: "WINDOWS_SECURITY"
    capture_all: true  # Capture ALL security events including 4800/4801 (lock/unlock)
  - name: "System"
    enabled: true
    source_name: "WINDOWS_SYSTEM"
  
  # PowerShell activity
  - name: "Microsoft-Windows-PowerShell/Operational"
    enabled: true
    source_name: "POWERSHELL"
  
  # WMI activity
  - name: "Microsoft-Windows-WMI-Activity/Operational"
    enabled: true
    source_name: "WMI"
  
  # Task Scheduler
  - name: "Microsoft-Windows-TaskScheduler/Operational"
    enabled: true
    source_name: "TASKSCHEDULER"
  
  # Windows Defender
  - name: "Microsoft-Windows-Windows Defender/Operational"
    enabled: true
    source_name: "DEFENDER"
  
  # Windows Firewall
  - name: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
    enabled: true
    source_name: "FIREWALL"
  
  # RDP/Session events
  - name: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    enabled: true
    source_name: "RDP_LOCAL"
  - name: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
    enabled: true
    source_name: "RDP_REMOTE"
  
  # BITS downloads
  - name: "Microsoft-Windows-Bits-Client/Operational"
    enabled: true
    source_name: "BITS"
  
  # AppLocker
  - name: "Microsoft-Windows-AppLocker/EXE and DLL"
    enabled: true
    source_name: "APPLOCKER_EXE"
  - name: "Microsoft-Windows-AppLocker/MSI and Script"
    enabled: true
    source_name: "APPLOCKER_MSI"
  
  # Code Integrity
  - name: "Microsoft-Windows-CodeIntegrity/Operational"
    enabled: true
    source_name: "CODE_INTEGRITY"
  
  # Application log (optional, can be noisy)
  - name: "Application"
    enabled: false
    source_name: "WINDOWS_APPLICATION"

sysmon:
  channel: "Microsoft-Windows-Sysmon/Operational"
  poll_interval_seconds: 5
  max_events: 200

security:
  enabled: true
  poll_interval_seconds: 5
  max_events: 100
```

## Windows Audit Policy Setup

**CRITICAL**: To capture Lock/Unlock events (4800/4801) and other security events, you must enable Windows auditing.

Run the provided setup script as Administrator:

```powershell
# Run as Administrator
.\setup_windows_audit.ps1
```

This script enables:
- **Logon/Logoff Events** (including Lock/Unlock - 4800/4801)
- **Account Logon Events**
- **Process Creation** (with command line logging)
- **Privilege Use**
- **Policy Changes**
- **Object Access** (file/registry monitoring)
- **Detailed Tracking**

**Note**: For domain environments, configure via Group Policy for consistent deployment.

## Sysmon Configuration

For maximum event capture, use the provided `sysmonconfig-max.xml` configuration:

```powershell
# Run as Administrator
# Apply maximum capture configuration
sysmon64.exe -c ..\sysmonconfig-max.xml
# Or if using 32-bit:
Sysmon.exe -c ..\sysmonconfig-max.xml

# Verify configuration
sysmon64.exe -c

# Restart Sysmon service to apply changes
Restart-Service Sysmon
# Or manually:
net stop Sysmon
net start Sysmon
```

The `sysmonconfig-max.xml` configuration:
- Enables all Sysmon event types (ProcessCreate, NetworkConnect, ImageLoad, FileCreate, Registry, DNS, WMI, etc.)
- Uses `onmatch="include"` for maximum visibility
- Keeps only minimal excludes for essential Windows telemetry noise
- Suitable for UEBA systems that need comprehensive log data

## Verification

After setup, verify that events are being collected:

1. **Lock/Unlock Events**: Lock and unlock your workstation (Win+L), then check Event Viewer:
   ```powershell
   Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4800 or EventID=4801)]]" | Select-Object -First 5
   ```

2. **PowerShell Events**: Run a PowerShell command and check:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Select-Object -First 5
   ```

3. **Agent Status**: Check the agent GUI for:
   - Events read per channel
   - Events sent to server
   - Spool backlog (should be 0 if server is reachable)
   - Last send error (should be empty if working correctly)

**Note:** The `sysmonconfig-max.xml` file is located in the repository root. This configuration logs all events with minimal exclusions for maximum visibility.

---

## Event Envelope

The agent wraps each event in a JSON object to identify its source:

```json
// Sysmon Event
{"source": "sysmon", "event": {"Id": 1, "Message": "Process Create..."}}

// Security Event
{"source": "windows_event", "event": {"Id": 4624, "Message": "An account was successfully logged on..."}}
```

---

## File Structure

```
agent/
├── src/
│   ├── gui.py               # Tkinter configuration GUI
│   └── sysmon_forwarder.py  # Event collection & forwarding
├── config/
│   └── agent_config.yaml    # Runtime configuration
├── dist/
│   └── SysmonAgent.exe      # Pre-built executable
├── run_agent.py             # Entry point
├── SysmonAgent.spec         # PyInstaller build spec
└── requirements.txt         # Dependencies (pyyaml)
```

---

## Requirements

- Windows 10/11 (or Windows Server)
- Sysmon installed and running
- Administrator privileges
- Python 3.8+ (only for building from source)

---

## Deploying with Task Scheduler

To run at Windows startup:

1. Open Task Scheduler (`taskschd.msc`)
2. Create Task → "Run with highest privileges"
3. Trigger: "At startup"
4. Action: Start program → `SysmonAgent.exe`

---

## Security Notes

- This is a **lab prototype** – no encryption or authentication
- Agent only makes **outbound** TCP connections
- For production, add TLS and API authentication

---

## License

MIT License – See [main README](../README.md) for details.
