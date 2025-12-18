# Risk Score Calculation - Complete Formula Reference

## Current Scoring Pipeline (As-Is After P0 MVP Fix)

### Pipeline 1: Real-Time Event Scoring (ingest.py → risk_engine.py)

**Location**: `server/src/server/risk/risk_engine.py:162` (`assess_risk` method)

**Trigger**: Every event ingested via `server/src/server/ingest.py:351`

#### Step-by-Step Formula

```
1. Component Scores (0-100 each):
   rule_score = rule_scorer.score(event, context_features)     [0-100]
   feature_score = _compute_feature_score(event)                [0-100]
   anomaly_score = anomaly_detector.detect(event, context)      [0-100]
   context_score = 0.0                                          [NOT IMPLEMENTED]

2. Combine Rule + Feature (sub-weights from features_config.yaml):
   rule_sub_weight = 0.6
   feature_sub_weight = 0.4
   
   combined_rule_feature = 0.6 * rule_score + 0.4 * feature_score

3. Final Risk Score (weights from thresholds.yaml - NORMALIZED):
   weights = {
       "rule": 0.4286,      # Normalized: 0.3/(0.3+0.4)
       "anomaly": 0.5714,   # Normalized: 0.4/(0.3+0.4)
       "context": 0.0       # Disabled until implemented
   }
   
   final_risk = weights["rule"] * combined_rule_feature + 
                 weights["anomaly"] * anomaly_score + 
                 weights["context"] * context_score
   
   Expanded:
   final_risk = 0.4286 * (0.6 * rule_score + 0.4 * feature_score) + 
                 0.5714 * anomaly_score + 
                 0.0 * context_score
   
   Simplified:
   final_risk = 0.25716 * rule_score + 
                0.17144 * feature_score + 
                0.5714 * anomaly_score

4. Risk Level Mapping (from features_config.yaml):
   if final_risk >= 80:  "critical"
   elif final_risk >= 60: "high"
   elif final_risk >= 40: "medium"
   elif final_risk >= 20: "low"
   else:                 "info"
```

#### Max Score Verification

With all component scores at 100:
```
combined_rule_feature = 0.6 * 100 + 0.4 * 100 = 100
final_risk = 0.4286 * 100 + 0.5714 * 100 = 42.86 + 57.14 = 100 ✓
risk_level = "critical" ✓
```

### Pipeline 2: Batch Anomaly Scan (run_anomaly_scan.py)

**Location**: `server/scripts/run_anomaly_scan.py:154` (`compute_anomaly_score`)

**Trigger**: Manual run or scheduled job

#### Formula

```
1. Anomaly Score (0.0-1.0):
   anomaly_score = compute_anomaly_score(event, baseline, global_baseline)
   
   Checks:
   - Unusual hour: +0.3 if true
   - Rare process: +0.4 if true
   - Rare domain: +0.3 if true
   
   anomaly_score = min(1.0, sum of checks)

2. Risk Score Conversion:
   risk_score = int(anomaly_score * 100)  [0-100]

3. Risk Level:
   if risk_score >= 80: "CRITICAL"
   elif risk_score >= 60: "HIGH"
   elif risk_score >= 40: "MEDIUM"
   else: "LOW"
```

**Note**: Batch scan does NOT use rule_score or feature_score (by design).

## Data Sources

### Database Tables
- `events` - Raw events with risk_score, rule_score, anomaly_score
- `baseline_stats` - Baseline profiles (hourly_histogram, common_processes, etc.)
- `app_settings` - Configuration (thresholds, windows, etc.)

### Configuration Files
- `server/src/server/risk/config/thresholds.yaml` - Main weights (NORMALIZED)
- `server/config/features_config.yaml` - Feature weights, sub-weights, risk_levels
- `server/config/mitre_mapping.yaml` - MITRE ATT&CK mappings

### Settings (app_settings table)
- `realtime_alert_threshold` (default: 80) - Real-time alert creation threshold
- `anomaly_threshold` (default: 0.7) - Batch scan threshold
- `dedup_window_minutes` (default: 60) - Alert deduplication window
- `baseline_window_hours` (default: 6) - Baseline training window

## Real-Time Alert Creation Flow

```
Event arrives → ingest.py:_process_line()
  ↓
Normalize → normalizer.py
  ↓
Risk assessment → risk_engine.assess_risk(event)
  ↓
Store event → storage.store_event(event)
  ↓
Check threshold → if event.risk_score >= realtime_alert_threshold (80):
  ├─→ Rate limit check (max 10 alerts/user/hour)
  ├─→ Build reasons from rule_score, anomaly_score, feature_score
  ├─→ Create Alert object
  ├─→ Enrich with MITRE mapping
  └─→ Store with deduplication (upsert_or_update_alert)
```

## Key Code Locations

### Risk Score Calculation
- **Real-time**: `server/src/server/risk/risk_engine.py:162` (`assess_risk`)
- **Batch**: `server/scripts/run_anomaly_scan.py:154` (`compute_anomaly_score`)

### Alert Creation
- **Real-time**: `server/src/server/ingest.py:371` (after event storage)
- **Batch**: `server/scripts/run_anomaly_scan.py:340` (Alert object creation)

### MITRE Mapping
- **Config**: `server/config/mitre_mapping.yaml`
- **Module**: `server/src/server/mitre_mapper.py`
- **Usage**: `enrich_alert(alert)` called in both pipelines

### Settings
- **Storage**: `server/src/server/storage.py:196` (`app_settings` table)
- **API**: `server/src/server/app.py:2234` (`/api/settings`)
- **UI**: `server/src/server/templates/settings.html`

## Worked Example

### Real-Time Alert (High-Risk Event)

**Input Event**:
- `rule_score = 90` (suspicious command detected)
- `feature_score = 80` (multiple suspicious features)
- `anomaly_score = 85` (IsolationForest detected anomaly)

**Calculation**:
```
combined_rule_feature = 0.6 * 90 + 0.4 * 80 = 54 + 32 = 86
final_risk = 0.4286 * 86 + 0.5714 * 85 = 36.86 + 48.57 = 85.43
risk_level = "critical" (>= 80)
```

**Alert Created**:
- `risk_score = 85`
- `risk_level = "CRITICAL"`
- `behavior = "realtime_risk_event"`
- `reasons = [{"type": "rule_hit", ...}, {"type": "high_anomaly", ...}]`
- `mitre_tactics = ["TA0001"]`
- `mitre_techniques = ["T1078"]`

### Batch Scan Alert (After-Hours Exfil)

**Input Event**:
- Login at 3am (unusual hour)
- Process: `rclone.exe` (rare process)
- Domain: `dropbox.com` (rare domain)

**Calculation**:
```
anomaly_score = 0.3 (unusual_hour) + 0.4 (rare_process) + 0.3 (rare_domain) = 1.0
risk_score = int(1.0 * 100) = 100
risk_level = "CRITICAL"
```

**Alert Created**:
- `risk_score = 100`
- `risk_level = "CRITICAL"`
- `behavior = "ueba_anomaly"`
- `reasons = [{"type": "unusual_hour", ...}, {"type": "rare_process", ...}, {"type": "rare_domain", ...}]`
- `mitre_tactics = ["TA0010"]` (from mapping)
- `mitre_techniques = ["T1048.003"]` (from mapping)

## Gaps / TODO

1. ✅ **FIXED**: CRITICAL reachability (weights normalized)
2. ✅ **FIXED**: MITRE mapping (config-driven, auditable)
3. ✅ **FIXED**: Real-time alerting (ingest pipeline)
4. ⚠️ **PENDING**: Context score implementation (still 0.0)
5. ⚠️ **PENDING**: Batch scan could use rule_score (currently anomaly-only)
6. ⚠️ **PENDING**: Rate limiting could be improved (per-behavior limits)

## Testing

Run acceptance test:
```bash
python server/scripts/test_risk_score_reachability.py
```

Expected output:
```
✅ PASS: final_risk can reach 100
✅ PASS: risk_level can be CRITICAL (>= 80)
✅ PASS: Formula is mathematically correct
```

