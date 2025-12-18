# MITRE API Smoke Tests

## New Endpoints

### 1. MITRE Summary
```bash
# Get MITRE ATT&CK summary (top tactics/techniques)
curl "http://localhost:8080/api/mitre/summary?time_range=24h"

# Expected response:
{
  "total_mitre_alerts": 22,
  "top_techniques": [{"id": "T1059", "count": 12}, ...],
  "top_tactics": [{"id": "TA0002", "count": 14}, ...],
  "time_range": "24h"
}

# Time range options: 1h, 24h, 7d, 30d
```

### 2. Alerts with MITRE Filter
```bash
# Get only alerts with MITRE mapping
curl "http://localhost:8080/api/alerts?has_mitre=true"

# Filter by specific technique
curl "http://localhost:8080/api/alerts?mitre_technique=T1059"

# Filter by specific tactic
curl "http://localhost:8080/api/alerts?mitre_tactic=TA0002"

# Combine filters
curl "http://localhost:8080/api/alerts?has_mitre=true&mitre_technique=T1059&limit=10"
```

## Verification Checklist
- [ ] `/api/mitre/summary?time_range=24h` returns 200 + valid JSON
- [ ] `/api/alerts?has_mitre=true` returns fewer or equal alerts vs no filter
- [ ] `/api/alerts?mitre_technique=T1059` filters correctly
- [ ] MITRE fields present in alert response: `mitre_tactics`, `mitre_techniques`
