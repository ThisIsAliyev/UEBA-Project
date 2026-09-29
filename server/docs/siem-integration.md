# SIEM Integration Guide

This document describes the SIEM (Elasticsearch/ELK) integration for the UEBA platform.

## Overview

The UEBA server now exports all normalized events and alerts to Elasticsearch in real-time. This enables:
- Centralized log analysis in Kibana
- Correlation with other security events
- Long-term storage and compliance
- Advanced analytics and visualization

## Configuration

### Server Configuration

Edit `server/config/server_config.yaml`:

```yaml
siem:
  enabled: true
  elasticsearch_url: "http://10.10.4.151:9200"
  batch_size: 100
  batch_interval_seconds: 5.0
  timeout_seconds: 10.0
```

### Elasticsearch Connection

- **URL**: `http://10.10.4.151:9200` (default Elasticsearch port)
- **Authentication**: If required, set `ES_USERNAME` and `ES_PASSWORD` environment variables

## Data Export

### Events Index

- **Index Pattern**: `ueba-events-YYYY.MM.DD` (daily rotation)
- **Contains**: All normalized security events from Sysmon and Windows Event Viewer
- **Fields**: Process info, network connections, risk scores, anomaly scores, etc.

### Alerts Index

- **Index Pattern**: `ueba-alerts-YYYY.MM.DD` (daily rotation)
- **Contains**: UEBA behavior detection alerts
- **Fields**: Behavior type, risk score, host, user, alert details

## Testing

### 1. Test Elasticsearch Connectivity

```bash
curl http://10.10.4.151:9200
```

Expected response: JSON with Elasticsearch cluster information

### 2. Start UEBA Server

```bash
cd server
python -m src.server.main
```

Look for log message: `SIEM exporter started`

### 3. Verify Data Export

Check server logs for SIEM export messages:
```bash
tail -f logs/server.log | grep SIEM
```

### 4. Query Elasticsearch

**Check events index:**
```bash
curl "http://10.10.4.151:9200/ueba-events-*/_search?size=1&pretty"
```

**Check alerts index:**
```bash
curl "http://10.10.4.151:9200/ueba-alerts-*/_search?size=1&pretty"
```

### 5. View in Kibana

1. Open Kibana: `http://10.10.4.151:5601`
2. Go to **Management** → **Stack Management** → **Index Patterns**
3. Create index pattern: `ueba-events-*`
4. Create index pattern: `ueba-alerts-*`
5. Go to **Discover** to explore data

## Index Mappings

### Events Index Fields

- `@timestamp`: Event timestamp
- `event.kind`: "event"
- `event.category`: Event category (process, network, auth, etc.)
- `host.name`: Source hostname
- `user.name`: User account
- `process.name`: Process name
- `process.command_line`: Command line arguments
- `ueba.risk_score`: Risk score (0-100)
- `ueba.risk_level`: Risk level (info/low/medium/high/critical)
- `ueba.rule_score`: Rule-based score
- `ueba.anomaly_score`: ML anomaly score
- `source.ip`: Source IP address
- `destination.ip`: Destination IP address

### Alerts Index Fields

- `@timestamp`: Alert timestamp
- `event.kind`: "alert"
- `host.name`: Affected host
- `user.name`: Affected user
- `ueba.alert.behavior`: Behavior type (failed_login_burst, suspicious_path_execution, etc.)
- `ueba.alert.risk_score`: Alert risk score
- `ueba.alert.status`: Alert status (open/closed)
- `ueba.alert.summary`: Alert summary message

## Troubleshooting

### SIEM Exporter Not Starting

1. Check configuration in `server_config.yaml`
2. Verify `enabled: true` in SIEM config
3. Check server logs for initialization errors
4. Verify Elasticsearch URL is correct and reachable

### No Data in Elasticsearch

1. Check network connectivity: `ping 10.10.4.151`
2. Test Elasticsearch: `curl http://10.10.4.151:9200`
3. Check server logs for export errors
4. Verify events are being ingested (check SQLite database)

### Authentication Errors

If Elasticsearch requires authentication:
1. Set `ES_USERNAME` and `ES_PASSWORD` environment variables
2. Restart UEBA server

### Performance Issues

- Reduce `batch_size` if experiencing timeouts
- Increase `timeout_seconds` if network is slow
- Check Elasticsearch cluster health

## Architecture

```
Windows Agent → UEBA Server (Ingest) → Normalize → Risk Assessment
                                                      ↓
                                              SIEM Exporter
                                                      ↓
                                              Elasticsearch
                                                      ↓
                                                  Kibana
```

## Files Modified

- `server/src/server/siem/export.py`: SIEM export module
- `server/src/server/config.py`: Added SIEMConfig
- `server/src/server/ingest.py`: Added export calls
- `server/src/server/app.py`: Added exporter initialization
- `server/config/server_config.yaml`: Added SIEM configuration

## Support

For issues or questions, check:
- Server logs: `logs/server.log`
- Elasticsearch logs: Check ELK server logs
- Kibana Dev Tools: Use for advanced queries
