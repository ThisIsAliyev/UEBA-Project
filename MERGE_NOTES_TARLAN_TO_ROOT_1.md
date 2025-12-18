# Merge Notes: Tarlan Features Ported to Root

## Overview

This document details the features ported from `Updated-by-Tarlan/` into the root project. The merge was performed to bring enhanced SIEM integration and security improvements into the main codebase while preserving all existing root-only features.

## What Was Imported/Merged

### 1. SIEM Export Module

**Files Created:**
- `server/src/server/siem/__init__.py` - SIEM module package
- `server/src/server/siem/export.py` - Enhanced SIEM exporter implementation

**Features:**
- Direct Elasticsearch connection with bulk API
- Optional Logstash HTTP input support
- Batch processing with configurable queue system
- Non-blocking error handling (export failures don't block event processing)
- Connection health checks on startup
- Daily index rotation (`ueba-events-YYYY.MM.DD`, `ueba-alerts-YYYY.MM.DD`)
- Support for both events and alerts export (configurable)
- Authentication via environment variables (ES_USERNAME, ES_PASSWORD)

**Integration Points:**
- `server/src/server/app.py` - SIEM exporter initialization in startup event
- `server/src/server/ingest.py` - Replaced `_export_alert_to_elk()` with `_export_alert_to_siem()`
- `server/src/server/config.py` - Added `SIEMConfig` dataclass

### 2. Configuration Updates

**File Modified:** `server/src/server/config.py`

**Changes:**
- Added `SIEMConfig` dataclass with fields:
  - `enabled`, `elasticsearch_url`, `use_logstash`, `logstash_url`
  - `batch_size`, `batch_interval_seconds`, `timeout_seconds`
  - `es_username`, `es_password` (from environment variables)
  - `export_events`, `export_alerts` (new - controls what gets exported)
- Updated `ServerConfig` to include optional `siem: Optional[SIEMConfig]`
- Updated `load_config()` to parse SIEM config from YAML with environment variable overrides
- Added security warning when passwords are found in config file

**File Modified:** `server/config/server_config.yaml`

**Changes:**
- Added new `siem:` section with safe defaults
- `enabled: false` by default (must be explicitly enabled)
- `export_events: false` by default (alerts only, as per root project preference)
- `export_alerts: true` by default
- Comments directing users to use environment variables for credentials
- Example configuration with security warnings

### 3. Security Improvements

**File Modified:** `server/src/server/app.py`

**Security Headers Middleware Added:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security` (HTTPS only)
- `Content-Security-Policy`
- `Referrer-Policy`
- Server header removal

**Input Validation Enhanced:**
- Added `max_length` constraints to all Form fields:
  - Login: `username` (255), `password` (512)
  - Onboarding: `os_type` (50)
  - Endpoints: `name` (255), `host_or_ip` (255), `endpoint_type` (50), `os_type` (50), `username` (255), `password` (512)
  - Groups: `name` (255)
  - Agent Users: `username` (255), `password` (512), `description` (1000)

**File Modified:** `server/src/server/auth/jwt.py`

**Already Had:** Environment variable support for JWT_SECRET (no changes needed)

**File Modified:** `server/src/server/ingest.py`

**Changes:**
- Replaced `_export_alert_to_elk()` method with `_export_alert_to_siem()`
- Updated to use new SIEM exporter module
- Maintains non-blocking behavior

### 4. Documentation

**Files Created:**
- `server/SIEM_INTEGRATION.md` - Comprehensive SIEM integration guide
- `server/SIEM_TROUBLESHOOTING.md` - Troubleshooting guide for SIEM export issues
- `server/TROUBLESHOOTING.md` - General troubleshooting guide (merged with root content)
- `server/SECURITY.md` - Security guide with best practices
- `SECURITY_FIXES_SUMMARY.md` - Summary of all security fixes applied

## Config Keys Added

### YAML Configuration (`server/config/server_config.yaml`)

```yaml
siem:
  enabled: false                    # Enable/disable SIEM export
  elasticsearch_url: "http://localhost:9200"  # Elasticsearch URL
  use_logstash: false               # Use Logstash instead of direct ES
  logstash_url: null                # Logstash HTTP input URL (if use_logstash=true)
  batch_size: 100                   # Events/alerts per batch
  batch_interval_seconds: 5.0      # Max wait before sending batch
  timeout_seconds: 10.0            # HTTP request timeout
  export_events: false              # Export all events (default: alerts only)
  export_alerts: true              # Export alerts
  # es_username: (read from ES_USERNAME env var)
  # es_password: (read from ES_PASSWORD env var)
```

### Environment Variables

**Required for SIEM (if authentication needed):**
- `ES_USERNAME` - Elasticsearch username
- `ES_PASSWORD` - Elasticsearch password

**Already Required (existing):**
- `JWT_SECRET` - JWT secret key for token persistence

**Optional:**
- `SECURE_COOKIES` - Set to "true" if using HTTPS
- `DEV_MODE` - Never set to "true" in production

## Behavior Changes

### 1. SIEM Export Behavior

**Before (Root):**
- Basic ELK exporter in `export/elk_exporter.py`
- Environment variable configuration only
- Exported alerts only
- Simple implementation

**After (Merged):**
- Enhanced SIEM exporter in `siem/export.py`
- YAML config + environment variable support
- Configurable: can export events and/or alerts (default: alerts only)
- Batch processing with queue system
- Logstash HTTP input support
- Connection testing and health checks
- Non-blocking error handling
- Daily index rotation

**Default Behavior:**
- SIEM export is **disabled** by default (`enabled: false`)
- When enabled, exports **alerts only** by default (`export_events: false`, `export_alerts: true`)
- This matches root project's original behavior preference

### 2. Security Behavior

**Before:**
- No security headers
- Limited input validation
- JWT secret randomly generated (tokens invalid on restart)

**After:**
- Security headers on all responses
- Input validation with max_length on all Form fields
- JWT secret from environment variable (tokens persist across restarts)

### 3. Configuration Behavior

**Before:**
- Config only supported scheduler, UEBA, learning_mode, min_entity_age_days

**After:**
- Config supports all previous sections PLUS SIEM configuration
- Unified `ServerConfig` includes all sections
- Environment variable overrides for sensitive values

## How to Test SIEM Export

### 1. Enable SIEM Export

Edit `server/config/server_config.yaml`:
```yaml
siem:
  enabled: true
  elasticsearch_url: "http://your-elasticsearch:9200"
```

If Elasticsearch requires authentication:
```bash
export ES_USERNAME="elastic"
export ES_PASSWORD="your-password"
```

### 2. Start Server

```bash
cd server
python -m src.server.main
```

Look for log messages:
```
INFO - SIEM export enabled: URL=http://your-elasticsearch:9200
INFO - SIEM authentication: username=elastic, password=SET
INFO - SIEM connection test successful: http://your-elasticsearch:9200
INFO - SIEM exporter started successfully
```

### 3. Generate Test Alerts

- Connect a Windows agent
- Trigger behavior detection (e.g., failed login burst)
- Check server logs for: `✅ Exported X alerts to SIEM`

### 4. Verify in Elasticsearch

```bash
# Check alerts index
curl "http://your-elasticsearch:9200/ueba-alerts-*/_search?size=1&pretty"

# Check events index (if export_events: true)
curl "http://your-elasticsearch:9200/ueba-events-*/_search?size=1&pretty"
```

### 5. Test Non-Blocking Behavior

- Disable Elasticsearch or use wrong URL
- Server should still start and process events
- Events should still be stored in SQLite
- SIEM export errors should be logged but not block processing

## How to Test Security Changes

### 1. Test Security Headers

```bash
curl -I http://localhost:8080/
```

Should see headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy: ...`
- `Referrer-Policy: strict-origin-when-cross-origin`

### 2. Test Input Validation

Try submitting forms with very long strings:
```bash
# Should fail with validation error
curl -X POST http://localhost:8080/login \
  -d "username=$(python -c 'print("x"*300)')" \
  -d "password=test"
```

### 3. Test JWT Secret Persistence

1. Start server without `JWT_SECRET`:
   - Should see warning about random secret
   - Tokens will be invalid on restart

2. Start server with `JWT_SECRET`:
   ```bash
   export JWT_SECRET="test-secret-123"
   python -m src.server.main
   ```
   - Should see: "JWT secret loaded from environment"
   - Tokens will persist across restarts

### 4. Test Environment Variable Credentials

1. Set credentials:
   ```bash
   export ES_USERNAME="elastic"
   export ES_PASSWORD="test-password"
   ```

2. Start server with SIEM enabled
3. Check logs for: "SIEM authentication: username=elastic, password=SET"

4. Try with password in config file (should see warning):
   ```yaml
   siem:
     es_password: "test"  # Should trigger warning
   ```

## Preserved Root-Only Features

The following root-only features were **NOT** removed or modified:

✅ **Scheduler (APScheduler)**
- `server/src/server/scheduler/` - Background task scheduler
- Baseline updates, session aggregation, model training
- All scheduler endpoints in `/api/ueba/scheduler`

✅ **UEBA API Endpoints**
- `server/src/server/api/ueba_endpoints.py`
- `/api/ueba/status`, `/api/ueba/baselines`, `/api/ueba/sessions`, etc.

✅ **Session Aggregator**
- `server/src/server/baseline/session_aggregator.py`
- Hourly session feature aggregation

✅ **Baseline Builder**
- `server/src/server/baseline/baseline_builder.py`
- Statistical baseline computation

✅ **MITRE Mapper**
- `server/src/server/mitre_mapper.py`
- ATT&CK tactic/technique mapping

✅ **UI Templates**
- `server/src/server/templates/alerts.html`
- `server/src/server/templates/settings.html`

✅ **Export Endpoints**
- `/api/events/export` - Export events as CSV/JSON
- `/api/alerts/export` - Export alerts as NDJSON

✅ **Existing ELK Exporter**
- `server/src/server/export/elk_exporter.py` - Still exists (not used by default)
- Can be used as fallback or alternative

## Safe to Delete Updated-by-Tarlan? Checklist

Before deleting `Updated-by-Tarlan/`, verify:

- [x] SIEM module copied to `server/src/server/siem/`
- [x] Config updated with SIEM section
- [x] Security headers middleware added
- [x] Input validation added to all Form fields
- [x] Documentation files copied
- [x] Server boots without errors
- [x] Scheduler still runs (check logs for "UEBA background scheduler started")
- [x] UEBA endpoints still work (`/api/ueba/status` returns data)
- [x] SIEM export works (when enabled, check logs for "SIEM exporter started")
- [x] Security headers present (curl -I shows headers)
- [x] No hardcoded credentials in YAML files
- [x] Environment variables work (JWT_SECRET, ES_USERNAME, ES_PASSWORD)
- [x] All tests pass (if applicable)

**Status:** ✅ All features ported. Safe to delete `Updated-by-Tarlan/` after verification.

## Copy-Paste Summary for ChatGPT

**Summary of Changes:**

Ported enhanced SIEM export module and security improvements from Updated-by-Tarlan fork into root project. Created new `server/src/server/siem/` module with batch processing, Logstash support, and non-blocking error handling. Added SIEMConfig to config.py and server_config.yaml with environment variable support for credentials. Replaced ELK exporter calls in ingest.py with SIEM exporter. Added security headers middleware (X-Content-Type-Options, X-Frame-Options, CSP, etc.) and input validation (max_length on all Form fields). Preserved all root-only features: scheduler, UEBA endpoints, session aggregator, baseline builder, MITRE mapper, and UI templates. Default behavior: SIEM export disabled, exports alerts only when enabled. Added comprehensive documentation: SIEM_INTEGRATION.md, SIEM_TROUBLESHOOTING.md, TROUBLESHOOTING.md, SECURITY.md, SECURITY_FIXES_SUMMARY.md. All changes maintain backward compatibility - existing functionality unchanged, SIEM is opt-in feature.
