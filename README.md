# UEBA Platform with AI-Powered Threat Detection

**An open-source User and Entity Behavior Analytics (UEBA) platform that ingests Sysmon logs, enriches them with AI and threat intelligence, and detects anomalous activity in real-time.**

This project provides a complete telemetry pipeline: collecting Windows Sysmon events, analyzing them with a local LLM, enriching IOCs via n8n, scoring risk based on behavior, and displaying results in a live web dashboard.

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Repository Structure](#repository-structure)
4. [Technology Stack](#technology-stack)
5. [Setup & Installation](#setup--installation)
6. [License](#license)

---

## Features

| Feature | Description |
|---|---|
| **Centralized Logging** | Collects Sysmon and Windows Security events from multiple endpoints into a single server. |
| **AI-Powered Analysis** | Uses a local Ollama LLM to analyze suspicious event chains and provide structured verdicts (Malicious/Suspicious/Benign). |
| **Behavior Baselining** | Learns normal user/host activity (processes, hours, chains) and flags deviations. |
| **Threat Intel Enrichment** | Integrates with n8n to enrich IOCs (hashes, IPs, domains) using VirusTotal and AbuseIPDB. |
| **Risk Scoring Engine** | Calculates a dynamic risk score (0-100) for events by combining rule matches, baseline deviation, AI analysis, and threat intel. |
| **Whitelist/Blacklist** | Suppresses noise from known-good processes and escalates known-bad patterns. |
| **Real-Time Dashboard** | FastAPI-powered web UI to view events and alerts as they happen. |
| **Asynchronous & Non-Blocking** | AI and n8n calls are handled in background queues to ensure the ingest pipeline is never blocked. |
| **Secure by Design** | AI Server is protected by API key and IP whitelisting; Ollama is bound to localhost. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         VMware Network: 192.168.213.0/24                     │
│                                                                              │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐          │
│  │ Windows Agent   │    │ Web Server      │    │ AI Server       │          │
│  │ 192.168.213.135 │    │ 192.168.213.136 │    │ 192.168.213.138 │          │
│  │                 │    │                 │    │                 │          │
│  │ - Sysmon        │───▶│ - FastAPI :8080 │───▶│ - FastAPI :8000 │          │
│  │ - Security Logs │    │ - Ingest :9000  │    │ - Ollama :11434 │          │
│  │                 │    │                 │    │   (localhost)   │          │
│  └─────────────────┘    └────────┬────────┘    └─────────────────┘          │
│                                  │                                           │
│                                  │ HTTPS                                     │
│                                  ▼                                           │
│                         ┌─────────────────┐                                  │
│                         │ n8n.cloud       │                                  │
│                         │ (VirusTotal,    │                                  │
│                         │  AbuseIPDB)     │                                  │
│                         └─────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1.  **Ingest**: The **Windows Agent** sends Sysmon/Security logs to the **Web Server** on TCP port 9000.
2.  **Normalize & Score**: The Web Server normalizes the event, checks it against baselines and whitelists/blacklists, and calculates a preliminary risk score.
3.  **Enrich (Async)**:
    *   If the score is uncertain (e.g., 40-70), the event is sent to the **AI Server** for deep analysis by the Ollama LLM.
    *   If the event contains IOCs (hashes, IPs), it's sent to **n8n** for reputation checks.
4.  **Finalize Score**: Enrichment results are returned to the Web Server, which calculates a final risk score.
5.  **Alert & Visualize**: High-risk events generate alerts and all data is streamed to the web dashboard.

---

## Repository Structure

```
UEBA-Project/
│
├── README.md                    # You are here
│
├── agent/                       # Windows Sysmon Agent
│   ├── src/                     # Agent source code
│   ├── config/                  # agent_config.yaml.example (copy to agent_config.yaml)
│   ├── dist/SysmonAgent.exe     # Pre-built agent
│   └── README.md                # Agent-specific documentation
│
├── agent-linux/                 # Linux Agent
│   └── README.md                # Linux agent documentation
│
├── server/                      # Main Web Server (FastAPI)
│   ├── src/server/
│   │   ├── ai/                  # AI & n8n client, queue, scoring
│   │   ├── baseline/            # Behavior baseline & list engine
│   │   ├── risk/                # Risk engine (integrates all components)
│   │   ├── ingest.py            # TCP log ingest
│   │   └── main.py              # Server entry point
│   ├── config/                  # Server configuration files
│   ├── docs/                    # Architecture, SIEM, security, troubleshooting
│   ├── .env.example             # Environment variable template
│   └── README.md                # Server-specific documentation
│
├── ai_server/                   # AI Analysis Server (FastAPI + Ollama)
│   ├── src/                     # AI server source code
│   │   ├── services/            # Ollama client and prompt builder
│   │   └── middleware/          # API key and IP auth
│   ├── .env.example             # Environment variable template
│   └── README.md                # AI server documentation
│
└── docs/                        # Project documentation
    ├── README.md                # Documentation index
    └── engineering-notes/       # Historical fix reports & root-cause analyses
```

---

## Documentation

Start at the [documentation index](docs/README.md).

| Guide | Description |
|---|---|
| [Quick start](docs/quickstart.md) | Fastest path to a running server and agent |
| [How to run](docs/how-to-run.md) | Full run instructions for every component |
| [Scoring formula](docs/scoring-formula.md) | How the risk score is calculated |
| [Server architecture](server/docs/architecture-guide.md) | UEBA engine architecture and data flow |
| [Server security](server/docs/security.md) | Security model, authentication and hardening |
| [Troubleshooting](server/docs/troubleshooting.md) | Diagnosing common problems |


---

## Technology Stack

| Component | Technology | Purpose |
|---|---|---|
| **AI Server** | FastAPI, Ollama, httpx | LLM-based event analysis. |
| **Web Server** | FastAPI, Uvicorn, SQLite | Main application, data storage, and dashboard. |
| **Agent** | Python, PyInstaller | Windows event collection and forwarding. |
| **Enrichment** | n8n.cloud | IOC reputation checks via external APIs. |
| **Core Libraries** | Pydantic, httpx, PyYAML | Data validation, async HTTP, and configuration. |

---

## Setup & Installation

For detailed setup instructions, see the sections below, the [documentation index](docs/README.md), and the component-specific README files in each directory.

### Step 1: Clone and Navigate

```bash
git clone <repository-url>
cd HACKATHON-PROJECT/server
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Create Required Directories

```bash
mkdir -p data logs
```

### Step 5: Configure the Server (Optional)

Edit `config/server_config.yaml` to customize ports and settings:

```yaml
# TCP port for receiving Sysmon events
ingest_port: 9000

# HTTP port for web dashboard
web_port: 8080

# Database settings
database:
  path: "data/events.db"
  max_events: 100000

# Logging
logging:
  level: "INFO"
  file: "logs/server.log"
```

### Step 6: Start the Server

**Option A: Using the main module (recommended)**

```bash
python -m src.server.main
```

**Option B: Using uvicorn directly**

```bash
uvicorn src.server.app:app --host 0.0.0.0 --port 8080
```

**Option C: With custom ports**

```bash
python -m src.server.main --web-port 8080 --ingest-port 9000
```

### Expected Output

```
========================================
  UEBA Event Viewer Server
========================================
  Ingest Port: 9000 (TCP)
  Web Port:    8080 (HTTP)
========================================

INFO:     Started server process
INFO:     Waiting for application startup
INFO:     Application startup complete
INFO:     Uvicorn running on http://0.0.0.0:8080
```

### Step 7: Open Firewall Ports

```bash
sudo ufw allow 8080/tcp   # Web dashboard
sudo ufw allow 9000/tcp   # Event ingest
sudo ufw reload
```

### Step 8: Access the Dashboard

Open a browser and navigate to:

```
http://<server-ip>:8080/
```

To find your server's IP address:

```bash
ip addr show | grep inet
# or
hostname -I
```

### What the Normalization Layer Does

When raw Sysmon JSON arrives, the normalizer:

1. **Parses timestamps** → Converts to UTC ISO format
2. **Extracts host/user** → From `MachineName`, `UserId` fields
3. **Extracts process info** → Process name, PID, parent process, command line
4. **Extracts network info** → Source/destination IPs and ports
5. **Maps Event IDs** → Converts numeric IDs to descriptions (e.g., `1` → "Process Create")
6. **Generates summaries** → Human-readable message for each event
7. **Stores to SQLite** → Indexed for fast queries

---

## Setup – Windows Agent

### Prerequisites

1. **Sysmon must be installed** and actively logging events
   - Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
   - Install with: `sysmon64.exe -accepteula -i` (uses default config)

2. **Administrator privileges** are required to read Sysmon logs

### Configure Sysmon for Maximum Capture

For maximum event capture, replace the default Sysmon configuration with `sysmonconfig-max.xml`:

```powershell
# Run as Administrator
# Apply maximum capture configuration
sysmon64.exe -c sysmonconfig-max.xml
# Or if using 32-bit:
Sysmon.exe -c sysmonconfig-max.xml

# Restart Sysmon service to apply changes
Restart-Service Sysmon
# Or manually:
net stop Sysmon
net start Sysmon
```

**Note:** The `sysmonconfig-max.xml` configuration logs all events with minimal exclusions, generating significantly more events than the default configuration. Ensure your agent and server can handle the increased throughput.

### Configure Windows Event Log Sizes

Limit Windows Event Log storage while ensuring the agent captures all events:

```powershell
# Run as Administrator
# Sysmon operational log (256MB)
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:268435456

# Security log (512MB)
wevtutil sl "Security" /ms:536870912

# System log (256MB)
wevtutil sl "System" /ms:268435456

# Application log (256MB)
wevtutil sl "Application" /ms:268435456
```

### Configure Windows Audit Policy

Enable high-value Security events for comprehensive monitoring:

```powershell
# Run as Administrator
# Enable Process Creation auditing (with command line)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enable Logon/Logoff auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable

# Enable Account Lockout auditing
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

# Enable File System auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

### Option A: Use Pre-Built Executable (Easiest)

The pre-built executable is located at:

```
agent/dist/SysmonAgent.exe
```

1. Copy `SysmonAgent.exe` to your desired location
2. Run as Administrator (right-click → Run as administrator)
3. A configuration GUI will appear:
   - Enter the **server IP** (e.g., `192.168.56.101`)
   - Enter the **Port** (default: `9000`)
   - Check **"Remember settings"** to save the configuration
   - Click **Start**
4. The agent begins streaming events in the background

To stop the agent, press `Ctrl+C` in the console window.

### Option B: Build from Source

**Step 1: Install Python dependencies**

```powershell
cd agent
pip install -r requirements.txt
pip install pyinstaller
```

**Step 2: Run directly (for testing)**

```powershell
python run_agent.py
```

**Step 3: Build standalone executable**

Using the spec file:

```powershell
python -m PyInstaller SysmonAgent.spec
```

Or with a one-liner:

```powershell
python -m PyInstaller --onefile --noconsole --name SysmonAgent run_agent.py
```

The executable will be created at `dist/SysmonAgent.exe`.

### Configuration File

Settings are stored in `config/agent_config.yaml`:

```yaml
server:
  ip: "192.168.56.101"    # Server IP
  port: 9000              # Ingest port
  remember: true          # Save settings

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

sysmon:
  channel: "Microsoft-Windows-Sysmon/Operational"
  poll_interval_seconds: 5   # How often to check for new events
  max_events: 200            # Max events per poll cycle
```

**Key Features:**
- **Near Real-Time Forwarding**: Events sent in 1-second batches (configurable)
- **Durable Spool Queue**: Events spooled to disk if server unavailable, automatically drained on reconnect
- **Bookmark Persistence**: Last record ID per channel saved to disk, preventing data loss on restart
- **Multi-Channel Support**: Collect from Sysmon, Security, System, Application, and PowerShell logs

### Running at Startup (Task Scheduler)

To run the agent automatically when Windows starts:

1. Open **Task Scheduler** (`taskschd.msc`)
2. Click **Create Task** (not "Create Basic Task")
3. **General** tab:
   - Name: `SysmonAgent`
   - Check: "Run with highest privileges"
   - Check: "Run whether user is logged on or not"
4. **Triggers** tab:
   - New → Begin the task: "At startup"
5. **Actions** tab:
   - New → Action: "Start a program"
   - Program: `C:\path\to\SysmonAgent.exe`
6. Click **OK** and enter your password

---

## End-to-End Demo

Follow this workflow to see the complete system in action:

### 1. Start the Server

```bash
cd server
source venv/bin/activate
python -m src.server.main
```

Verify it's running by opening `http://<server-ip>:8080/` in a browser.

### 2. Start the Windows Agent

Run `SysmonAgent.exe` as Administrator:
- Enter the server IP (e.g., `192.168.56.101`)
- Enter port `9000`
- Click **Start**

### 3. Generate Activity on Windows

Open and close some programs to generate Sysmon events:
- Open Command Prompt or PowerShell
- Launch Notepad, Calculator, or any application
- Browse the web
- Create or delete files

### 4. View Events in Real-Time

1. Open the dashboard at `http://<server-ip>:8080/`
2. Events should appear within seconds (2-5 second refresh)
3. Use the filters to search by:
   - Host name
   - Event type (Process Create, Network Connect, etc.)
   - Time range
4. Click any event row to see full details including:
   - Process name and path
   - Command line arguments
   - Parent process
   - Network connections
   - Raw JSON data

### Quick Test with Netcat

If you don't have the Windows agent ready, test the server with a simulated event:

```bash
echo '{"TimeCreated":"2024-11-29T10:30:00Z","Id":1,"LevelDisplayName":"Information","Message":"Process Create:\nImage: C:\\Windows\\System32\\cmd.exe\nProcessId: 1234\nCommandLine: cmd.exe /c dir","ProviderName":"Microsoft-Windows-Sysmon","MachineName":"WORKSTATION-01","UserId":"DOMAIN\\user"}' | nc <server-ip> 9000
```

---

## Security

- **AI Server**: Protected by API key and IP whitelisting. Ollama is bound to localhost and not exposed to the network.
- **Web Server**: Listens on public ports but communicates with the AI server on a private network.
- **Agent**: Only makes outbound connections to the Web Server.
- **Secrets**: API keys and webhook URLs are managed via `.env` files and are not committed to the repository.

> This project is a prototype. For production use, consider implementing TLS for agent-server communication and more robust authentication for the web dashboard.

---

## License

MIT License - Use at your own risk.

This project was created for a 24-hour UEBA/Sysmon hackathon.

---

## Contributors

Built during the UEBA Hackathon 2024.
