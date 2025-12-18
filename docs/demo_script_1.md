# Demo Script (10-15 minutes)

## Minute 0-2: System Overview

**Speaker**: 
> "We built a Windows-native UEBA system. It collects 15+ log sources, normalizes them, builds ML baselines, detects anomalies, and exports to SIEM."

**Show**:
1. Architecture diagram (slides)
2. Open dashboard: http://localhost:8080
   - Live event feed (scrolling)
   - Stats: "1,234 events collected, 3 alerts"

## Minute 2-5: Scenario 1 Demo (After-Hours Data Exfil)

**Setup**:
1. Terminal 1: Show agent running
   ```bash
   cd agent
   python src/sysmon_forwarder.py
   ```

2. Terminal 2: Simulate attack
   ```powershell
   # Change time to 3am (or use replay)
   Set-Date -Date "2025-12-16 03:15:00"
   
   # Login (triggers Security 4624)
   # Open Chrome, navigate to dropbox.com
   Start-Process chrome "https://www.dropbox.com"
   
   # Create large file
   fsutil file createnew C:\temp\sensitive.zip 500000000
   
   # Reset time
   Set-Date -Date (Get-Date)
   ```

3. **Dashboard** (refresh after 30 sec):
   - New alert: "CRITICAL: After-hours data exfiltration"
   - Click alert → Detail page

**Show**:
- **Reasons section**:
  - ❌ Login at 3am (baseline: 8am-7pm)
  - ❌ Rare domain: dropbox.com
  - ❌ Volume spike: 500MB
- **Evidence timeline**: 8 events
- **MITRE badge**: TA0010 (Exfiltration)

**Narrate**:
> "Notice the system caught the unusual login hour, rare domain, and volume spike. The evidence timeline shows the full attack chain."

## Minute 5-7: ML Baseline Explanation

**Terminal**:
```bash
# Show training script
python scripts/train_baselines.py --hours 6

# Output:
# [INFO] Training baselines for 25 users...
# [INFO] User: john.doe
#   - hourly_histogram: [0, 0, 0, 5, 10, 15, ...]  # 8am-7pm peak
#   - common_processes: outlook.exe (50%), chrome.exe (30%)
```

**SQL Query** (show in DB browser):
```sql
SELECT * FROM baseline_stats 
WHERE entity_id = 'john.doe' 
  AND feature_name = 'hourly_histogram';
```

**Narrate**:
> "Our ML system builds per-user baselines over 6 hours (configurable). For John, normal hours are 8am-7pm. When he logged in at 3am, the system flagged it."

## Minute 7-9: SIEM Integration

**Terminal**:
```bash
# Export alerts
curl http://localhost:8080/api/alerts/export > alerts.ndjson

# Show NDJSON
cat alerts.ndjson | jq .

# Output:
# {
#   "@timestamp": "2025-12-16T03:15:00Z",
#   "alert.severity": "CRITICAL",
#   "user.name": "john.doe",
#   "threat.tactic.id": ["TA0010"],
#   ...
# }
```

**Narrate**:
> "Alerts export as NDJSON. Filebeat ingests them into Elasticsearch. Security analysts see them in Kibana with MITRE context."

## Minute 9-11: Additional Scenarios (Quick)

**Scenario 2** (Privilege Escalation):
- Show pre-recorded alert
- Highlight: Registry modification, scheduled task
- MITRE: TA0004

**Scenario 3** (Credential Dumping):
- Show alert: mimikatz.exe detected
- Evidence: LSASS access
- MITRE: TA0006

## Minute 11-12: Analyst Workflow

**Show UI**:
1. Alerts list: filter by severity (CRITICAL)
2. Click alert → Detail page
3. Click "Mark as True Positive"
4. Alert status updates

**Narrate**:
> "Analysts can triage alerts, see evidence, and provide feedback. This feeds into future model training."

## Minute 12: Wrap-Up

**Key Points**:
- ✅ Windows-native, agent-based collection
- ✅ ML baselines (per-user profiles)
- ✅ Anomaly detection (baseline deviations)
- ✅ SIEM integration (Elastic)
- ✅ MITRE ATT&CK mapping
- ✅ Explainability (reasons + evidence)

**Close**: > "Questions?"

## Fallback Plan

If live demo fails:
1. Use replay script: `python scripts/replay_demo.py --scenario after_hours`
2. Show screenshots
3. Use pre-populated DB

