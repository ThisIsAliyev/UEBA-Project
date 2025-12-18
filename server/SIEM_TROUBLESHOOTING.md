# SIEM Export Troubleshooting Guide

## Problem: 401 Unauthorized Errors

If you see errors like:
```
ERROR - SIEM export HTTP error 401: missing authentication credentials
ERROR - Authentication failed - check es_username and es_password in config
```

This means Elasticsearch requires authentication but credentials are not configured.

## Solution 1: Use Environment Variables (Recommended)

Set the following environment variables before starting the server:

```bash
export ES_USERNAME="elastic"
export ES_PASSWORD="your-elasticsearch-password"
```

Then restart the server.

## Solution 2: Temporary Config File (For Testing Only)

If you need to test quickly, you can temporarily uncomment the credentials in `server_config.yaml`:

```yaml
siem:
  enabled: true
  elasticsearch_url: "https://10.10.4.151:9200"
  es_username: "elastic"
  es_password: "your-password-here"  # ⚠️ Only for testing!
```

**⚠️ WARNING**: Never commit credentials to version control!

## Solution 3: Check Elasticsearch Connection

Test if Elasticsearch is accessible and what authentication it requires:

```bash
# Test without auth (if Elasticsearch allows it)
curl https://10.10.4.151:9200/_cluster/health

# Test with auth
curl -u elastic:your-password https://10.10.4.151:9200/_cluster/health
```

## Verify Configuration

After setting credentials, check the server logs on startup. You should see:

```
INFO - SIEM export enabled: URL=https://10.10.4.151:9200
INFO - SIEM authentication: username=elastic, password=SET
INFO - SIEM connection test successful: https://10.10.4.151:9200
INFO - SIEM exporter started successfully
```

If you see warnings about missing credentials, the environment variables are not being read.

## Check Health Endpoint

You can check SIEM status via the health endpoint:

```bash
curl http://localhost:8080/health | jq .siem
```

This will show:
- `enabled`: Whether SIEM export is enabled
- `running`: Whether the exporter is running
- `has_credentials`: Whether credentials are configured
- `events_queued`: Number of events waiting to be sent
- `alerts_queued`: Number of alerts waiting to be sent

## Common Issues

### Issue: Environment variables not loaded
**Solution**: Make sure to export variables in the same shell session where you start the server, or use a `.env` file with a tool like `python-dotenv`.

### Issue: Wrong credentials
**Solution**: Verify credentials work with curl first, then update environment variables.

### Issue: Elasticsearch not accessible
**Solution**: Check network connectivity, firewall rules, and Elasticsearch URL.

### Issue: SSL certificate errors
**Solution**: The code disables SSL verification for self-signed certificates. For production, use proper CA-signed certificates.
