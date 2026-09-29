# MITRE GUI Integration — QA Verification Checklist

## Prerequisites
```bash
cd c:\Users\Student\Downloads\Team-5-Project-master\server
python -m uvicorn src.server.app:app --host 127.0.0.1 --port 8080
```

---

## 1. Backend API Checks

### 1.1 Filter: has_mitre=true
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/alerts?has_mitre=true" -UseBasicParsing | Select-Object -ExpandProperty Content
```
**Expected:** JSON with `alerts` array, all items have non-empty `mitre_techniques` or `mitre_tactics`

### 1.2 Filter: mitre_technique
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/alerts?mitre_technique=T1059" -UseBasicParsing | Select-Object -ExpandProperty Content
```
**Expected:** Only alerts containing `T1059` in `mitre_techniques`

### 1.3 MITRE Summary
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:8080/api/mitre/summary?time_range=24h" -UseBasicParsing | Select-Object -ExpandProperty Content
```
**Expected:**
```json
{
  "total_mitre_alerts": <number>,
  "top_techniques": [{"id": "T1059", "count": N}, ...],
  "top_tactics": [{"id": "TA0002", "count": N}, ...],
  "time_range": "24h"
}
```

---

## 2. GUI Checks

| Check | Steps | Expected |
|-------|-------|----------|
| Sidebar MITRE link | Open http://127.0.0.1:8080, look at sidebar | "MITRE" item visible with target icon |
| MITRE page loads | Click MITRE in sidebar | Page shows summary cards + alert list |
| MITRE filter works | Type `T1059` in Technique filter, click Apply | Only T1059 alerts shown |
| Alert list chips | Open `/alerts`, look at MITRE column | Technique chips visible (T1059, T1003, etc.) |
| Chip click | Click any technique chip in alerts list | Navigates to `/mitre?technique=T1059` |
| Alert detail MITRE | Click "View" on MITRE-tagged alert | MITRE section visible with technique links |
| Alert detail non-MITRE | View alert without MITRE tags | MITRE section hidden |

---

## 3. Test Scenarios

### Scenario A: PowerShell (T1059)
1. Ensure a PowerShell detection alert exists (rule R001 in core_top25.yaml)
2. Open `/alerts` page
3. **Verify:** Alert row shows `T1059` chip
4. Click chip
5. **Verify:** MITRE page opens, filtered to T1059
6. Check summary card: T1059 in "Top Techniques"

### Scenario B: Credential Dumping (T1003)
1. Ensure LSASS access alert exists (rule R002/R003)
2. Open `/mitre` page
3. **Verify:** T1003 appears in "Top Techniques"
4. Filter by `T1003`
5. **Verify:** Only credential dumping alerts shown

### Scenario C: Non-MITRE Exclusion
1. Find or create an alert with no MITRE mapping
2. Open `/mitre` page
3. **Verify:** Alert NOT visible (only has_mitre=true shown)
4. Open `/alerts` page
5. **Verify:** Same alert shows `-` in MITRE column

---

## 4. Demo Script (3 minutes)

### Step 1: Show Sidebar (30 sec)
1. Open http://127.0.0.1:8080
2. Point to sidebar: **"New MITRE link added here"**
3. 📸 **Screenshot 1:** Sidebar with MITRE highlighted

### Step 2: Show MITRE Page (1 min)
1. Click MITRE in sidebar
2. Point to summary cards: **"Top techniques and tactics from last 24h"**
3. Show filter panel: **"Can filter by technique, tactic, severity"**
4. 📸 **Screenshot 2:** MITRE page with summary cards + filters

### Step 3: Show Alert List Labels (30 sec)
1. Navigate to `/alerts`
2. Point to MITRE column: **"New column shows technique chips"**
3. Hover over a chip: **"Clickable - links to MITRE page"**

### Step 4: Show Alert Detail (1 min)
1. Click "View" on any MITRE-tagged alert
2. Scroll to MITRE section: **"Links to ATT&CK website + related alerts"**
3. 📸 **Screenshot 3:** Alert detail with MITRE section visible

---

## 5. Screenshots to Capture

| # | Page | What to Show |
|---|------|--------------|
| 1 | Sidebar | MITRE nav item highlighted |
| 2 | /mitre | Summary cards + filter panel + alert list |
| 3 | /alerts/{id} | MITRE ATT&CK Mapping section with technique badges |

---

## 6. Pass/Fail Criteria

| Criteria | Pass |
|----------|------|
| MITRE sidebar link works | ☐ |
| MITRE page loads without errors | ☐ |
| has_mitre filter returns only MITRE alerts | ☐ |
| technique filter works correctly | ☐ |
| Summary counts are accurate | ☐ |
| Alert list shows chips for MITRE alerts | ☐ |
| Chip click navigates to MITRE page | ☐ |
| Alert detail shows MITRE section | ☐ |
| Non-MITRE alerts excluded from MITRE page | ☐ |
