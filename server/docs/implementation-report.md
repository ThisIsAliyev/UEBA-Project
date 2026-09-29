# UEBA Risk Scoring Engine - Implementation Report

## Summary

Implemented a complete rule-based UEBA (User and Entity Behavior Analytics) risk scoring engine with:
- 25 high-fidelity detection rules (Core Pack)
- Event scoring (0-100, capped)
- Context modifiers (off_hours, rare_host, privileged_user, etc.)
- Entity aggregation with dedup and decay
- Alert generation with explainability
- Flood prevention controls

---

## Files Modified

### 1. `server/src/server/models.py`
**Changes:** Added Sysmon-specific fields to `NormalizedEvent` model

New fields added:
- `source_image` - Sysmon source process image path
- `target_image` - Sysmon target process image path  
- `granted_access` - Sysmon ID 10 access rights (hex)
- `call_trace` - Sysmon ID 10 call stack
- `start_address` - Sysmon ID 8 thread start address
- `start_module` - Sysmon ID 8 module name
- `start_function` - Sysmon ID 8 function name
- `new_thread_id` - Sysmon ID 8 new thread ID
- `target_object` - Registry key path
- `registry_details` - Registry value data
- `service_name`, `service_file_name`, `service_type`, `service_start_type` - Service fields
- `task_name`, `task_content` - Scheduled task fields
- `share_name`, `share_path`, `relative_target_name` - Share access fields
- `ticket_encryption_type`, `ticket_options`, `service_sid` - Kerberos fields

### 2. `server/src/server/normalizer.py`
**Changes:** Added `extract_sysmon_specific_fields()` function

Extracts fields for:
- **ID 8 (CreateRemoteThread):** SourceImage, TargetImage, StartAddress, StartModule, StartFunction, NewThreadId
- **ID 10 (ProcessAccess):** SourceImage, TargetImage, GrantedAccess, CallTrace
- **ID 12/13/14 (Registry):** TargetObject, Details

**Critical Fix:** Sysmon ID 8 does NOT have GrantedAccess field (only ID 10 does)

### 3. `server/src/server/storage.py`
**Changes:** Added UEBA storage tables and methods

New tables:
- `rule_hits` - Stores every rule match with evidence
- `entity_risk` - Stores aggregated entity scores (1h/24h windows)
- `ueba_alerts` - Stores generated alerts with full explainability

New methods:
- `store_rule_hits()` - Store rule hit records
- `store_entity_risk()` - Upsert entity risk scores
- `get_entity_risk()` - Get entity scores
- `store_ueba_alert()` - Store UEBA alerts
- `get_ueba_alerts()` - Query alerts with filtering
- `get_rule_hits()` - Query rule hits
- `get_top_risky_entities()` - Get top risky users/hosts

---

## Files Added

### 1. `server/src/server/ueba/__init__.py`
UEBA module initialization, exports main classes.

### 2. `server/src/server/ueba/rule_loader.py`
**Detection Rule Schema & Loader**

Classes:
- `DetectionRule` - Rule definition dataclass
- `MatchCondition` - Field match condition
- `MitreMapping` - MITRE ATT&CK mapping
- `RuleLoader` - YAML rule loader with validation

Supported operators:
- `equals`, `not_equals`, `contains`, `not_contains`
- `startswith`, `endswith`, `regex`
- `contains_any`, `endswith_any`, `startswith_any`, `equals_any`
- `gt`, `gte`, `lt`, `lte`, `in_list`, `not_in_list`

### 3. `server/src/server/ueba/scoring_engine.py`
**Main Scoring Engine**

Classes:
- `EventScore` - Event scoring result with matched rules
- `EntityScore` - Aggregated entity score
- `ContextModifiers` - UEBA context modifiers
- `EntityAggregator` - Entity score aggregation with dedup/decay
- `UEBAScorer` - Main scoring orchestrator

Features:
- Event scoring: `event_score = min(100, max(base_scores) + bonus)`
- Bonus: +5 per additional high-confidence match
- Context modifiers:
  - `off_hours`: +10 if outside user's normal hours
  - `rare_host_for_user`: +15 if first-seen host
  - `rare_process_for_user`: +10 if first-seen process
  - `privileged_user`: 1.2x multiplier
  - `high_value_asset`: 1.2x multiplier
- Entity aggregation with configurable decay (0.5x per hour)
- Deduplication within configurable window (default 5 min)

### 4. `server/src/server/ueba/alert_manager.py`
**Alert Generation & Flood Prevention**

Classes:
- `AlertThresholds` - Configurable thresholds
- `UEBAAlert` - Alert with full explainability
- `RuleHit` - Rule hit record for storage
- `FloodController` - Rate limiting and flood prevention
- `AlertManager` - Alert generation orchestrator

Thresholds (configurable):
- Investigate: entity_1h >= 60
- Alert: entity_1h >= 80
- Critical: entity_1h >= 120 OR single event >= 90 with high confidence

Flood prevention:
- Max 5 alerts per entity per hour
- Alert deduplication within 15 minutes
- Graceful degradation with queue

### 5. `server/config/rules/core_top25.yaml`
**Top-25 Detection Rules**

Categories covered:
- **Credential Access (5 rules):** R001-R005
  - LSASS access, memory dumps, explicit credentials, Kerberoasting, browser creds
- **Lateral Movement (5 rules):** R006-R010
  - PsExec, WMI remote, WinRM, RDP, admin shares
- **Persistence (4 rules):** R011-R014
  - Scheduled tasks, Run keys, WMI subscriptions, services
- **Defense Evasion (5 rules):** R015-R019
  - Log clearing, wevtutil, security tool disable, PowerShell, AMSI bypass
- **Malware-like (6 rules):** R020-R025
  - CreateRemoteThread, process hollowing, DLL loading, Office spawning, certutil, mshta

### 6. `server/config/ueba_config.yaml`
UEBA configuration file with all tunable parameters.

### 7. `server/scripts/test_ueba_engine.py`
Test harness that replays sample events and prints scoring results.

---

## Architecture

```
Event Flow:
┌─────────┐    ┌────────────┐    ┌─────────────┐    ┌──────────────┐
│  Agent  │───>│  Ingest    │───>│ Normalizer  │───>│ UEBA Scorer  │
└─────────┘    └────────────┘    └─────────────┘    └──────────────┘
                                                            │
                    ┌───────────────────────────────────────┘
                    │
                    v
            ┌───────────────┐    ┌─────────────────┐    ┌─────────────┐
            │ Rule Matcher  │───>│ Context Mods    │───>│ Aggregator  │
            └───────────────┘    └─────────────────┘    └─────────────┘
                    │                                          │
                    v                                          v
            ┌───────────────┐                         ┌─────────────────┐
            │  Rule Hits    │                         │  Entity Scores  │
            │   (DB)        │                         │     (DB)        │
            └───────────────┘                         └─────────────────┘
                                                              │
                                                              v
                                                      ┌─────────────────┐
                                                      │ Alert Manager   │
                                                      └─────────────────┘
                                                              │
                                                              v
                                                      ┌─────────────────┐
                                                      │  UEBA Alerts    │
                                                      │     (DB)        │
                                                      └─────────────────┘
```

---

## Scoring Model

### Event Score (0-100)
```
event_score = min(100, max(rule.base_score for matched rules) + bonus)
bonus = 5 * (high_confidence_matches - 1)  # if > 1 high-conf match
```

### Context Modifiers
Applied after rule matching:
1. Additive: off_hours (+10), rare_host (+15), rare_process (+10)
2. Multiplicative: privileged_user (1.2x), high_value_asset (1.2x)
3. Final score capped at 100

### Entity Aggregation
```
entity_score = sum(event_scores with decay)
decay = 0.5 ^ (hours_since_event)
```

Deduplication: Same (rule_id + entity + key_fields) within N minutes counts once.

---

## Test Results

Test harness output shows:
- 7 sample events processed
- 7 rule matches across 6 events
- 8 alerts generated
- Correct scoring with modifiers applied
- Entity aggregation working correctly

Sample detections:
- LSASS access (R001): Score 90, Critical alert
- PowerShell encoded (R018): Score 85
- Registry Run key (R012): Score 75
- CreateRemoteThread (R020): Score 95, Critical alert
- Security log cleared (R015): Score 100, Critical alert
- Office spawning PowerShell (R018+R023): Score 90 (bonus applied)

---

## Integration Points

To integrate with existing ingest pipeline, add to `ingest.py`:

```python
from .ueba import get_ueba_scorer, get_alert_manager

# After normalize_event()
ueba_scorer = get_ueba_scorer()
event_score, user_score, host_score = ueba_scorer.process_event(event)

# Check for alerts
alert_manager = get_alert_manager(storage=self.storage)
alerts = alert_manager.evaluate_for_alert(event_score, user_score, host_score)

# Store rule hits and alerts
if event_score.matched_rules:
    rule_hits = alert_manager.create_rule_hit(event, event_score)
    self.storage.store_rule_hits(rule_hits)

for alert in alerts:
    alert.entity_id = event.user if alert.entity_type == 'user' else event.host
    self.storage.store_ueba_alert(alert)
```

---

## Next Steps

1. **Integration:** Wire UEBA scorer into ingest pipeline
2. **UI:** Add UEBA alerts view to web dashboard
3. **API:** Add endpoints for rule hits, entity scores, alerts
4. **Tuning:** Adjust thresholds based on environment
5. **Expansion:** Add remaining 125 rules to reach 150 total
6. **Baselines:** Implement baseline loading from DB for modifiers
