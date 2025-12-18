# P0 MVP Fix Summary: Risk Score Reachability + MITRE Mapping + Real-time Alerting

## Changes Made

### 1. Fix #1: Real-time CRITICAL Reachability (Math Bug Fix)

**Problem**: Weights summed to 0.7 (rule=0.3 + anomaly=0.4 + context=0.0), making max score 70 → CRITICAL (80+) unreachable.

**Solution**: Normalized weights so active weights sum to 1.0.

**File**: `server/src/server/risk/config/thresholds.yaml`

**Before**:
```yaml
weights:
  rule: 0.3
  anomaly: 0.4
  context: 0.3
```

**After**:
```yaml
weights:
  rule: 0.4286     # Normalized: 0.3/(0.3+0.4) = 0.428571...
  anomaly: 0.5714  # Normalized: 0.4/(0.3+0.4) = 0.571428...
  context: 0.0     # Disabled until implemented
```

**Formula Verification**:
- With `rule_score=100`, `feature_score=100`, `anomaly_score=100`:
  - `combined_rule_feature = 0.6 * 100 + 0.4 * 100 = 100`
  - `final_risk = 0.4286 * 100 + 0.5714 * 100 = 42.86 + 57.14 = 100` ✓
  - `risk_level = "critical"` (>= 80) ✓

### 2. Fix #2: MITRE ATT&CK Mapping (Config-Driven)

**Created Files**:
- `server/config/mitre_mapping.yaml` - Mapping configuration
- `server/src/server/mitre_mapper.py` - Mapping module

**Mappings Added**:
- `after_hours_data_exfil` → TA0010 / T1048.003
- `privilege_escalation` → TA0004, TA0003 / T1548, T1053.005
- `credential_dumping` → TA0006 / T1003.001
- `realtime_risk_event` → TA0001 / T1078 (default for real-time alerts)
- `ueba_anomaly` → TA0001 / T1078 (default for batch alerts)
- Rule-based behaviors (failed_login_burst, suspicious_path_execution, etc.)

**Integration Points**:
- `server/scripts/run_anomaly_scan.py` - Batch alerts enriched
- `server/src/server/ingest.py` - Real-time alerts enriched

### 3. Fix #3: Real-time Alert Creation in Ingest Pipeline

**File**: `server/src/server/ingest.py` (after line 369)

**Features**:
- Alert creation when `event.risk_score >= threshold` (default: 80)
- Rate limiting: max 10 alerts per user per hour
- Deduplication: uses existing `upsert_or_update_alert()` method
- MITRE enrichment: automatically applied
- Reasons: built from `rule_score`, `anomaly_score`, `feature_score`

**Settings Added**:
- `realtime_alert_threshold` (default: 80) - Configurable via `/api/settings` or UI

### 4. SIEM Export: MITRE ECS Fields

**File**: `server/src/server/app.py` - `/api/alerts/export` endpoint

**Added Fields**:
- `threat.framework: "MITRE ATT&CK"`
- `threat.tactic.id`: List of tactic IDs
- `threat.tactic.name`: Same as ID
- `threat.technique.id`: List of technique IDs
- `threat.technique.name`: Same as ID

### 5. UI: MITRE Badges on Alert Detail Page

**File**: `server/src/server/templates/alert_detail.html`

**Changes**:
- Tactics and techniques are now clickable links
- Tactic URLs: `https://attack.mitre.org/tactics/TA0010/`
- Technique URLs: `https://attack.mitre.org/techniques/T1048/003/` (sub-technique format)
- Shows "Not mapped" if no MITRE mapping exists

### 6. Settings UI: Real-time Alert Threshold

**File**: `server/src/server/templates/settings.html`

**Added**:
- Input field for `realtime_alert_threshold` (0-100)
- Validation in API endpoint

## Updated Scoring Formula

### Real-Time Scoring (risk_engine.py)

```
Step 1: Component Scores (0-100 each)
  rule_score = rule_scorer.score(event) [0-100]
  feature_score = _compute_feature_score(event) [0-100]
  anomaly_score = anomaly_detector.detect(event) [0-100]
  context_score = 0.0 [NOT IMPLEMENTED]

Step 2: Combine Rule + Feature
  combined_rule_feature = 0.6 * rule_score + 0.4 * feature_score

Step 3: Final Risk Score
  final_risk = 0.4286 * combined_rule_feature + 0.5714 * anomaly_score + 0.0 * context_score
  
  Expanded:
  final_risk = 0.4286 * (0.6 * rule_score + 0.4 * feature_score) + 0.5714 * anomaly_score
  final_risk = 0.25716 * rule_score + 0.17144 * feature_score + 0.5714 * anomaly_score

Step 4: Risk Level
  if final_risk >= 80: "critical"
  elif final_risk >= 60: "high"
  elif final_risk >= 40: "medium"
  elif final_risk >= 20: "low"
  else: "info"
```

**Max Score Verification**:
- `rule_score=100`, `feature_score=100`, `anomaly_score=100`:
- `final_risk = 0.25716 * 100 + 0.17144 * 100 + 0.5714 * 100 = 25.716 + 17.144 + 57.14 = 100` ✓

### Batch Scan Scoring (run_anomaly_scan.py)

**Unchanged** (as per requirements):
```
anomaly_score = compute_anomaly_score(event, baseline) [0.0-1.0]
risk_score = int(anomaly_score * 100) [0-100]
```

## Testing

### Acceptance Test Commands

See `docs/how_to_run.md` section "Quick Acceptance Test (P0 MVP Fix)".

### Manual Verification

1. **CRITICAL Reachability**:
   ```python
   # In Python console or test script
   rule_score = 100
   feature_score = 100
   anomaly_score = 100
   
   combined = 0.6 * rule_score + 0.4 * feature_score  # = 100
   final_risk = 0.4286 * combined + 0.5714 * anomaly_score
   # Should be ~100, risk_level should be "critical"
   ```

2. **Real-time Alerting**:
   - Send high-risk event (risk_score >= 80)
   - Check `/alerts` page within seconds
   - Verify alert has MITRE badges

3. **MITRE Mapping**:
   - Generate alert with behavior `after_hours_data_exfil`
   - Check DB: `mitre_tactics` should contain `["TA0010"]`
   - Check UI: Badge should link to MITRE website

4. **SIEM Export**:
   ```bash
   curl http://localhost:8080/api/alerts/export | jq '.["threat.framework"]'
   # Should output: "MITRE ATT&CK"
   ```

## Files Modified

1. `server/src/server/risk/config/thresholds.yaml` - Weight normalization
2. `server/config/mitre_mapping.yaml` - NEW: MITRE mappings
3. `server/src/server/mitre_mapper.py` - NEW: Mapping module
4. `server/src/server/ingest.py` - Real-time alert creation
5. `server/src/server/storage.py` - Added `realtime_alert_threshold` default
6. `server/scripts/run_anomaly_scan.py` - MITRE enrichment
7. `server/src/server/app.py` - SIEM export MITRE fields, settings validation
8. `server/src/server/templates/alert_detail.html` - MITRE badge links
9. `server/src/server/templates/settings.html` - Real-time threshold input
10. `docs/how_to_run.md` - Acceptance test commands

## Backward Compatibility

✅ All existing scripts continue to work:
- `train_baselines.py` - Unchanged
- `run_anomaly_scan.py` - Only added MITRE enrichment (non-breaking)
- Existing alerts in DB - Still readable (new fields are optional)

✅ Settings system:
- New setting `realtime_alert_threshold` has safe default (80)
- Existing settings unchanged

✅ API endpoints:
- `/api/alerts/export` - Added fields are optional (backward compatible)
- `/api/settings` - New setting added, existing ones unchanged

## Known Limitations

1. **Context Score**: Still 0.0 (not implemented) - weights normalized to compensate
2. **Batch vs Real-time**: Different scoring formulas (by design, per requirements)
3. **Rate Limiting**: Simple count-based (10 per user per hour) - could be improved
4. **MITRE Mapping**: Default fallback used if behavior not found in config

## Next Steps (Future)

- Implement context_score in risk engine
- Add more MITRE mappings for additional behaviors
- Improve rate limiting (sliding window, per-behavior limits)
- Add MITRE mapping UI for admins to edit mappings

