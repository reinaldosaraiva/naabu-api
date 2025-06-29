#!/bin/bash

echo "Testing local scan with simple target..."

# Test with localhost port that should be open (our own API)
curl -s -X POST http://localhost:8082/scan \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["127.0.0.1"],
    "ports": "8080",
    "enable_probes": false,
    "enable_deep_scan": false
  }' | jq '.'

echo -e "\nWaiting 10 seconds for scan to complete..."
sleep 10

echo -e "\nChecking database for results..."
docker exec naabu-api sqlite3 /data/naabu_api.db "SELECT scan_id, status, results FROM scan_jobs ORDER BY created_at DESC LIMIT 1;"