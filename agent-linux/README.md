# UEBA Linux Agent

Linux-based event collector and forwarder for the UEBA (User and Entity Behavior Analytics) system.

**Same workflow as Windows Agent** - GUI for server IP, username/password input, and dashboard approval.

## Features

- **GUI Configuration**: Same as Windows agent - enter server IP, username, password
- **Dashboard Approval**: Agent appears in Endpoint Management for admin approval
- **Journalctl Collection**: Collects events from systemd journal
- **Auth Log Collection**: Monitors `/var/log/auth.log` or `/var/log/secure`
- **Syslog Collection**: Monitors `/var/log/syslog` or `/var/log/messages`
- **Auditd Collection**: Collects Linux Audit Framework events
- **TLS Support**: Secure communication with the server
- **Spool Queue**: Durable event storage when server is unavailable

## Requirements

- Python 3.8+
- Linux with systemd (for journalctl)
- tkinter (GUI) - usually included with Python
- Root/sudo access (for reading protected log files)

## Installation

1. Clone or copy the agent-linux directory to the target Linux machine:
   ```bash
   scp -r agent-linux user@target:/opt/ueba-agent
   ```

2. Install dependencies:
   ```bash
   cd /opt/ueba-agent
   pip3 install -r requirements.txt
   
   # Install tkinter if not available
   sudo apt install python3-tk    # Debian/Ubuntu
   sudo dnf install python3-tkinter  # Fedora/RHEL
   ```

## Quick Start (GUI Mode - Same as Windows)

```bash
sudo python3 run_agent.py
```

A GUI window will open where you can:
1. Enter **Server IP** (e.g., 192.168.1.100)
2. Enter **Ingest Port** (default: 9000)
3. Enter **Web Port** (default: 8080)
4. Enter **Username** (from Agent Users page)
5. Enter **Password**
6. Click **Start Agent**

The agent will connect and wait for admin approval in the dashboard.

## Configuration File

Edit `config/agent_config.yaml` for headless/service mode:

```yaml
server:
  ip: 192.168.1.100    # UEBA server IP
  port: 9000           # Ingest port
  tls_enabled: false   # Enable TLS encryption

auth:
  enabled: true
  web_port: 8080       # Web server port
  username: "agent1"   # Created in Agent Users page
  password: "secret"   # Agent password

journalctl:
  enabled: true
  priority: 6          # 0-7 (6=info, 3=err)

auth_log:
  enabled: true

syslog:
  enabled: true

auditd:
  enabled: true
```

## Usage

### GUI Mode (Recommended - Same as Windows)
```bash
sudo python3 run_agent.py
```

### Headless Mode (for servers without display)
```bash
sudo python3 run_agent.py --no-gui
```

### Command Line Options
```bash
sudo python3 run_agent.py --server 192.168.1.100 --port 9000 --web-port 8080 --username agent1 --password secret
```

## Running as a Service

Create a systemd service file `/etc/systemd/system/ueba-agent.service`:

```ini
[Unit]
Description=UEBA Linux Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ueba-agent
ExecStart=/usr/bin/python3 /opt/ueba-agent/run_agent.py --no-gui
Restart=always
RestartSec=10
Environment=DISPLAY=

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ueba-agent
sudo systemctl start ueba-agent
```

Check status:
```bash
sudo systemctl status ueba-agent
sudo journalctl -u ueba-agent -f
```

## Log Sources

| Source | Log Path | Events |
|--------|----------|--------|
| Journalctl | systemd journal | All systemd unit events |
| Auth Log | /var/log/auth.log | SSH logins, sudo, PAM |
| Syslog | /var/log/syslog | System messages |
| Auditd | /var/log/audit/audit.log | Audit framework events |

## Dashboard Integration

Once the agent connects and is approved:
1. Go to **Endpoint Management** in the dashboard
2. Find the Linux endpoint in the list
3. View real-time events and status

## Troubleshooting

### Permission Denied
Some log files require root access:
```bash
sudo python3 run_agent.py
```

### No Events from Auditd
Ensure auditd is installed and running:
```bash
sudo apt install auditd  # Debian/Ubuntu
sudo yum install audit   # RHEL/CentOS
sudo systemctl start auditd
```

### Connection Refused
- Check server IP and port
- Verify firewall allows outbound connections to port 9000
- Ensure UEBA server is running

## Security Notes

- Store credentials securely
- Use TLS in production
- Run with minimal required permissions
- Regularly update the agent
