# UEBA Web Server

> **📖 For full project documentation, see the [main README](../README.md).**

This is the core component of the UEBA platform. It is a FastAPI application responsible for ingesting logs, orchestrating analysis, and serving the web dashboard.

---

## Features

- **Log Ingestion**: Listens on a TCP port for logs from Windows agents.
- **Risk Orchestration**: Manages the entire analysis pipeline, from initial scoring to AI and threat intel enrichment.
- **Behavior Baselining**: Contains the `BaselineManager` to track normal activity and detect deviations.
- **Whitelist/Blacklist**: Uses the `ListEngine` to apply risk modifiers based on known-good/bad patterns.
- **Async Enrichment**: Communicates with the AI Server and n8n via non-blocking, asynchronous clients with circuit breakers and caching.
- **Database Storage**: Stores all events and alerts in a local SQLite database.
- **Web Dashboard**: Serves a real-time dashboard for viewing events and alerts.

---

## Architecture

```
                                  ┌──────────────────┐
                                  │   Windows Agent  │
                                  └────────┬─────────┘
                                           │ TCP :9000
┌──────────────────────────────────────────▼───────────────────────────────────────────────┐
│                                    UEBA Web Server                                       │
│                                                                                          │
│   ┌─────────────┐   ┌───────────────┐   ┌─────────────────┐   ┌──────────────────────┐   │
│   │ Ingest Server │──▶│  Risk Engine  │──▶│ Baseline Manager  │──▶│   List Engine  │   │
│   └─────────────┘   └───────┬───────┘   └─────────────────┘   └──────────────────────┘   │
│                              │                                                           │
│                              │ (If score is uncertain)                                   │
│                              ▼                                                           │
│   ┌────────────────┐   ┌─────────────┐                      ┌────────────────────────┐   │
│   │ AI Client      │──▶│ Analysis    │◀── (If IOCs exist) ──┤    n8n Client         │   │
│   │ (Circuit Breaker)│   │ Queue       │                      │ (Cache & Rate Limit) │   │
│   └────────────────┘   └─────────────┘                      └────────────────────────┘   │
│         │                      │ (Async Worker)                          │               │
│         │                      ▼                                         │               │
│         │         ┌─────────────────────────┐                            │               │
│         └────────▶│       AI Server         │                           │               │
│                   │ (192.168.213.138:8000)  │                            │               │
│                   └─────────────────────────┘                            │               │
│                                                                          │               │
│                                                                          ▼               │
│                                                                ┌──────────────────┐      │
│                                                                │    n8n.cloud     │      │
│                                                                └──────────────────┘      │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Event Envelope Format

The agent sends events wrapped in an envelope:

```json
{
  "source": "sysmon",
  "event": {
    "TimeCreated": "/Date(1732888200000)/",
    "Id": 1,
    "Message": "Process Create:\nImage: C:\\Windows\\cmd.exe\n...",
    "ProviderName": "Microsoft-Windows-Sysmon",
    "MachineName": "WORKSTATION01",
    ...
  }
}
```

```json
{
  "source": "windows_event",
  "event": {
    "TimeCreated": "/Date(1732888200000)/",
    "Id": 4624,
    "Message": "An account was successfully logged on...",
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "MachineName": "WORKSTATION01",
    "TargetUserName": "john.doe",
    ...
  }
}
```

**Backward Compatibility**: If `source` is missing, the server defaults to `"sysmon"`.

---

## Normalized Event Schema

All events (regardless of source) are normalized into:

| Field | Type | Description |
|-------|------|-------------|
| `id` | int | Auto-incremented database ID |
| `timestamp` | datetime | Event timestamp (UTC) |
| **`source`** | str | Event source: `"sysmon"` or `"windows_event"` |
| `host` | str | Source machine name |
| `user` | str | User account |
| `event_id` | int | Windows Event ID |
| `level` | str | Severity level |
| `provider` | str | Event provider name |
| `category` | str | Event category (process, network, file, auth, etc.) |
| `process_name` | str | Process name (Sysmon events) |
| `process_id` | int | PID |
| `command_line` | str | Command line arguments |
| `source_ip` | str | Source IP (network/auth events) |
| `dest_ip` | str | Destination IP |
| `auth_result` | str | Authentication result (auth events) |
| `logon_type` | int | Windows logon type (auth events) |
| `message` | str | Human-readable summary |
| `raw_json` | str | Original JSON |

---

## Web Dashboard

The server provides two dashboard views:

### 1. Alerts Dashboard (`/`)
- UEBA behavior detection alerts
- Filter by behavior type
- Risk scoring

### 2. Events Viewer (`/events`)
- Raw event stream from all sources
- **Source filter**: All / Sysmon / Event Viewer
- Real-time updates via WebSocket
- Search and filtering

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Alerts Dashboard HTML |
| `/events` | GET | Events Viewer HTML |
| `/api/events` | GET | Query events (supports filters) |
| `/api/events/{id}` | GET | Single event by ID |
| `/api/events/sources` | GET | List of valid source types |
| `/api/stats` | GET | Event statistics (includes `by_source`) |
| `/api/alerts` | GET | Query UEBA alerts |
| `/api/alerts/stats` | GET | Alert statistics |
| `/api/ingest/status` | GET | Ingest server status |
| `/ws/events` | WebSocket | Real-time event stream |

### Query Parameters for `/api/events`

| Parameter | Description |
|-----------|-------------|
| `limit` | Max events (1-1000) |
| `offset` | Pagination offset |
| `since_id` | Events after this ID |
| `host` | Filter by hostname |
| `event_id` | Filter by Windows Event ID |
| **`source`** | Filter by source: `"sysmon"` or `"windows_event"` |

---

## Configuration

Edit `config/server_config.yaml`:

```yaml
# TCP port for receiving events (all sources)
ingest_port: 9000

# HTTP port for dashboard
web_port: 8080

database:
  path: "data/events.db"
  max_events: 100000

logging:
  level: "INFO"
  file: "logs/server.log"

web_ui:
  events_per_page: 100
  refresh_interval_ms: 2000
```

---

## File Structure

```
server/
├── src/
│   └── server/
│       ├── main.py          # Entry point
│       ├── app.py           # FastAPI application
│       ├── ingest.py        # TCP ingest server
│       ├── normalizer.py    # Multi-source normalization
│       ├── storage.py       # SQLite layer (with source column)
│       ├── models.py        # Pydantic models (EventSource enum)
│       ├── config.py        # Config loader
│       ├── behaviors/       # UEBA behavior detectors
│       └── templates/
│           ├── index.html   # Alerts Dashboard
│           └── events.html  # Events Viewer
├── config/
│   └── server_config.yaml   # Server settings
├── data/
│   └── events.db            # SQLite DB (auto-created)
├── logs/
│   └── server.log           # Application logs
└── requirements.txt         # Dependencies
```

---

## Firewall Setup

```bash
sudo ufw allow 8080/tcp   # Web dashboard
sudo ufw allow 9000/tcp   # Event ingest (both sources)
sudo ufw reload
```

---

## Testing

### Test Sysmon Event

```bash
echo '{"source":"sysmon","event":{"TimeCreated":"2024-11-29T10:30:00Z","Id":1,"LevelDisplayName":"Information","Message":"Process Create:\nImage: C:\\Windows\\System32\\cmd.exe\nProcessId: 1234","ProviderName":"Microsoft-Windows-Sysmon","MachineName":"TEST-PC"}}' | nc localhost 9000
```

### Test Windows Event (Security)

```bash
echo '{"source":"windows_event","event":{"TimeCreated":"2024-11-29T10:30:00Z","Id":4624,"LevelDisplayName":"Information","Message":"An account was successfully logged on.","ProviderName":"Microsoft-Windows-Security-Auditing","MachineName":"TEST-PC","TargetUserName":"testuser","TargetDomainName":"TESTDOMAIN"}}' | nc localhost 9000
```

---

## Data Flow: Sysmon Event

```
1. Windows Agent polls Microsoft-Windows-Sysmon/Operational
2. Agent wraps event: {"source": "sysmon", "event": {...}}
3. Agent sends JSON line to server:9000
4. Server parses envelope, extracts source="sysmon"
5. Server calls normalize_sysmon_event()
6. NormalizedEvent created with source=EventSource.SYSMON
7. Event stored in SQLite with source column
8. WebSocket broadcasts to dashboard
9. Dashboard displays with "Sysmon" badge
```

## Data Flow: Windows Event Viewer

```
1. Windows Agent polls Security log for events 4624/4625
2. Agent wraps event: {"source": "windows_event", "event": {...}}
3. Agent sends JSON line to server:9000
4. Server parses envelope, extracts source="windows_event"
5. Server calls normalize_security_event()
6. NormalizedEvent created with source=EventSource.WINDOWS_EVENT
7. Event stored in SQLite with source column
8. WebSocket broadcasts to dashboard
9. Dashboard displays with "Event Viewer" badge
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Events not appearing | Check `/api/ingest/status`, verify firewall |
| Wrong source shown | Verify agent sends correct `source` field |
| WebSocket errors | Dashboard falls back to polling automatically |
| Database errors | Check disk space, verify `data/` permissions |
| Old events show no source | Migration adds default `source='sysmon'` |

See logs: `tail -f logs/server.log`

---

## License

MIT License – See [main README](../README.md) for details.
