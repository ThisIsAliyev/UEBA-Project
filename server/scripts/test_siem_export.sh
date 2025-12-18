#!/bin/bash
# MVP P0: SIEM Export Test Script

echo "Testing SIEM export endpoint..."

# 1. Export alerts
curl -s http://localhost:8080/api/alerts/export?hours=24 > /tmp/alerts.ndjson

# 2. Validate NDJSON
if ! cat /tmp/alerts.ndjson | jq . > /dev/null 2>&1; then
    echo "❌ Invalid NDJSON"
    exit 1
fi

# 3. Count alerts
count=$(wc -l < /tmp/alerts.ndjson)
echo "✅ Exported $count alerts"

# 4. Validate structure
first_line=$(head -n 1 /tmp/alerts.ndjson)
if echo "$first_line" | jq -e '.@timestamp' > /dev/null 2>&1; then
    echo "✅ Valid ECS structure"
else
    echo "❌ Invalid ECS structure"
    exit 1
fi

# 5. Send to Elasticsearch (if available)
if curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo "Sending to Elasticsearch..."
    cat /tmp/alerts.ndjson | while read line; do
        curl -s -X POST "http://localhost:9200/insider-threat-alerts/_doc" \
             -H "Content-Type: application/json" \
             -d "$line" > /dev/null
    done
    echo "✅ Sent to Elasticsearch"
else
    echo "⚠️  Elasticsearch not available (skipping)"
fi

echo "✅ SIEM export test passed"

