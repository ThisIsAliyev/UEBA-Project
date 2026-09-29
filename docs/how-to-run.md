# How to Run UEBA MVP

## Prerequisites

- Python 3.10+
- Windows 10+ (for agent)
- SQLite 3

## Setup

### 1. Install Dependencies

```bash
cd server
pip install -r requirements.txt
```

### 2. Configure Agent

Edit `agent/config/agent_config.yaml`:
- Set `server_host` and `server_port`
- Enable desired channels in `channels` section

### 3. Run Server

```bash
cd server
python src/server/app.py
```

Server will start on `http://localhost:8080`

### 4. Run Agent (Windows)

```bash
cd agent
python src/sysmon_forwarder.py
```

## Training Baselines

### Initial Training

```bash
# Use settings default (6 hours) or specify window
python scripts/train_baselines.py --hours 6

# Or use days
python scripts/train_baselines.py --days 7
```

### Update Baselines (Incremental)

```bash
python scripts/train_baselines.py --update --hours 24
```

## Running Anomaly Scans

```bash
# Scan last 1 hour (default from settings)
python scripts/run_anomaly_scan.py --hours 1

# Custom threshold
python scripts/run_anomaly_scan.py --hours 1 --threshold 0.7

# Dry run (no alerts created)
python scripts/run_anomaly_scan.py --hours 1 --dry-run
```

## Settings Configuration

Access Settings page: `http://localhost:8080/settings`

Or use API:
```bash
# Get settings
curl http://localhost:8080/api/settings

# Update settings
curl -X POST http://localhost:8080/api/settings \
  -H "Content-Type: application/json" \
  -d '{"baseline_window_hours": "3", "anomaly_threshold": "0.7"}'
```

## SIEM Export

```bash
# Export alerts (NDJSON format)
curl http://localhost:8080/api/alerts/export > alerts.ndjson

# Validate
cat alerts.ndjson | jq .
```

## Demo Scenarios

See `docs/insider-threat-scenarios.md` for safe demo steps.

## Quick Acceptance Test (P0 MVP Fix)

### Test Real-time Alerting + MITRE Mapping

1. **Start server + agent**:
   ```bash
   # Terminal 1: Server
   cd server
   python src/server/app.py
   
   # Terminal 2: Agent (Windows)
   cd agent
   python src/sysmon_forwarder.py
   ```

2. **Trigger demo scenario**:
   ```bash
   python scripts/replay_demo.py --scenario after_hours
   ```

3. **Run batch scan** (if needed):
   ```bash
   python scripts/run_anomaly_scan.py --hours 1
   ```

4. **Verify in UI**:
   - Open: http://localhost:8080/alerts
   - Should show CRITICAL alert
   - Click alert → Detail page
   - Check: Reasons visible, MITRE badges clickable

5. **Verify SIEM export**:
   ```bash
   curl http://localhost:8080/api/alerts/export | head -n 3 | jq .
   ```
   - Should include `threat.framework: "MITRE ATT&CK"`
   - Should include `threat.tactic.id` and `threat.technique.id`

6. **Test real-time alerting**:
   - Send high-risk event (or use replay script)
   - Within seconds, alert should appear in `/alerts` page
   - Same behavior+user+host within dedup window should increment `occurrence_count`

### Test CRITICAL Reachability

1. **Check risk score calculation**:
   - With `rule_score=100`, `feature_score=100`, `anomaly_score=100`:
   - Formula: `final_risk = 0.18 * 100 + 0.12 * 100 + 0.4 * 100 = 18 + 12 + 40 = 70`
   - Wait, that's still 70! Let me check the formula again...
   - Actually: `combined_rule_feature = 0.6 * 100 + 0.4 * 100 = 100`
   - Then: `final_risk = 0.4286 * 100 + 0.5714 * 100 = 42.86 + 57.14 = 100` ✓

2. **Verify in code**:
   - Check `server/src/server/risk/config/thresholds.yaml`:
     - `rule: 0.4286`, `anomaly: 0.5714`, `context: 0.0`
   - Weights sum to 1.0 when context=0

## Troubleshooting

- **No baselines**: Run `train_baselines.py` first
- **No alerts**: Check anomaly threshold in settings (batch) or realtime_alert_threshold (real-time)
- **Agent not connecting**: Check firewall and server port
- **CRITICAL not reachable**: Verify thresholds.yaml weights sum to 1.0
- **MITRE badges not showing**: Check mitre_mapping.yaml exists and alert has behavior key

