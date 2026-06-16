#!/bin/bash
# =============================================================
#  Elasticsearch Setup Script
#  Runs once on first boot to:
#    1. Set kibana_system password
#    2. Create index templates for network-flows & windows-events
#    3. Set up ILM policies
# =============================================================

set -e

ES_URL="http://elasticsearch:9200"
ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-ThreatHunter@2024}"
KIBANA_PASSWORD="${KIBANA_PASSWORD:-ThreatHunter@2024}"

echo "⏳ Waiting for Elasticsearch to be ready..."
until curl -s -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL}/_cluster/health" | grep -qv '"status":"red"'; do
  sleep 5
  echo "   Still waiting..."
done
echo "✅ Elasticsearch is ready."

# -----------------------------------------------------------
# 1. Set kibana_system password
# -----------------------------------------------------------
echo "🔑 Setting kibana_system password..."
curl -s -X POST -u "elastic:${ELASTIC_PASSWORD}" \
  "${ES_URL}/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q '"acknowledged":true\|{}'
echo "✅ kibana_system password set."

# -----------------------------------------------------------
# 2. ILM Policy — 30-day hot, 60-day warm, then delete
# -----------------------------------------------------------
echo "📋 Creating ILM policy..."
curl -s -X PUT -u "elastic:${ELASTIC_PASSWORD}" \
  "${ES_URL}/_ilm/policy/threathunter-events-policy" \
  -H "Content-Type: application/json" -d '
{
  "policy": {
    "phases": {
      "hot":  { "min_age": "0ms",  "actions": { "rollover": { "max_age": "1d", "max_size": "5gb" } } },
      "warm": { "min_age": "30d",  "actions": { "shrink": { "number_of_shards": 1 } } },
      "delete":{ "min_age": "90d", "actions": { "delete": {} } }
    }
  }
}'
echo -e "\n✅ ILM policy created."

# -----------------------------------------------------------
# 3. Index Template — network-flows
# -----------------------------------------------------------
echo "📋 Creating index template: network-flows..."
curl -s -X PUT -u "elastic:${ELASTIC_PASSWORD}" \
  "${ES_URL}/_index_template/network-flows-template" \
  -H "Content-Type: application/json" -d '
{
  "index_patterns": ["network-flows-*"],
  "template": {
    "settings": {
      "number_of_shards": 2,
      "number_of_replicas": 0,
      "index.lifecycle.name": "threathunter-events-policy",
      "index.lifecycle.rollover_alias": "network-flows"
    },
    "mappings": {
      "properties": {
        "@timestamp":        { "type": "date" },
        "src_ip":            { "type": "ip" },
        "dst_ip":            { "type": "ip" },
        "src_port":          { "type": "integer" },
        "dst_port":          { "type": "integer" },
        "protocol":          { "type": "keyword" },
        "bytes_sent":        { "type": "long" },
        "bytes_recv":        { "type": "long" },
        "packets_sent":      { "type": "long" },
        "packets_recv":      { "type": "long" },
        "duration_ms":       { "type": "float" },
        "tcp_flags":         { "type": "keyword" },
        "anomaly_score":     { "type": "float" },
        "is_anomaly":        { "type": "boolean" },
        "severity":          { "type": "keyword" },
        "geo_src": {
          "properties": {
            "country_code": { "type": "keyword" },
            "city":         { "type": "keyword" },
            "location":     { "type": "geo_point" }
          }
        },
        "geo_dst": {
          "properties": {
            "country_code": { "type": "keyword" },
            "city":         { "type": "keyword" },
            "location":     { "type": "geo_point" }
          }
        }
      }
    }
  }
}'
echo -e "\n✅ network-flows template created."

# -----------------------------------------------------------
# 4. Index Template — windows-events
# -----------------------------------------------------------
echo "📋 Creating index template: windows-events..."
curl -s -X PUT -u "elastic:${ELASTIC_PASSWORD}" \
  "${ES_URL}/_index_template/windows-events-template" \
  -H "Content-Type: application/json" -d '
{
  "index_patterns": ["windows-events-*"],
  "template": {
    "settings": {
      "number_of_shards": 2,
      "number_of_replicas": 0,
      "index.lifecycle.name": "threathunter-events-policy",
      "index.lifecycle.rollover_alias": "windows-events"
    },
    "mappings": {
      "properties": {
        "@timestamp":        { "type": "date" },
        "event_id":          { "type": "integer" },
        "event_id_keyword":  { "type": "keyword" },
        "channel":           { "type": "keyword" },
        "computer":          { "type": "keyword" },
        "user":              { "type": "keyword" },
        "domain":            { "type": "keyword" },
        "logon_type":        { "type": "integer" },
        "process_name":      { "type": "keyword" },
        "parent_process":    { "type": "keyword" },
        "command_line":      { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
        "src_ip":            { "type": "ip" },
        "dst_ip":            { "type": "ip" },
        "description":       { "type": "text" },
        "raw_message":       { "type": "text" },
        "anomaly_score":     { "type": "float" },
        "is_anomaly":        { "type": "boolean" },
        "severity":          { "type": "keyword" },
        "mitre_tactic":      { "type": "keyword" },
        "mitre_technique":   { "type": "keyword" }
      }
    }
  }
}'
echo -e "\n✅ windows-events template created."

# -----------------------------------------------------------
# 5. Index Template — threat-alerts
# -----------------------------------------------------------
echo "📋 Creating index template: threat-alerts..."
curl -s -X PUT -u "elastic:${ELASTIC_PASSWORD}" \
  "${ES_URL}/_index_template/threat-alerts-template" \
  -H "Content-Type: application/json" -d '
{
  "index_patterns": ["threat-alerts-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp":       { "type": "date" },
        "alert_id":         { "type": "keyword" },
        "source_type":      { "type": "keyword" },
        "severity":         { "type": "keyword" },
        "anomaly_score":    { "type": "float" },
        "description":      { "type": "text" },
        "mitre_tactic":     { "type": "keyword" },
        "mitre_technique":  { "type": "keyword" },
        "src_ip":           { "type": "ip" },
        "dst_ip":           { "type": "ip" },
        "hostname":         { "type": "keyword" },
        "raw_event":        { "type": "object", "enabled": false },
        "status":           { "type": "keyword" },
        "acknowledged_by":  { "type": "keyword" },
        "acknowledged_at":  { "type": "date" }
      }
    }
  }
}'
echo -e "\n✅ threat-alerts template created."

# -----------------------------------------------------------
# 6. Bootstrap rolling indices with aliases
# -----------------------------------------------------------
echo "🔄 Bootstrapping rolling indices..."

for INDEX in "network-flows" "windows-events"; do
  curl -s -X PUT -u "elastic:${ELASTIC_PASSWORD}" \
    "${ES_URL}/${INDEX}-000001" \
    -H "Content-Type: application/json" -d "{
      \"aliases\": {
        \"${INDEX}\": {
          \"is_write_index\": true
        }
      }
    }" > /dev/null
  echo "   ✅ ${INDEX}-000001 created with alias."
done

curl -s -X PUT -u "elastic:${ELASTIC_PASSWORD}" \
  "${ES_URL}/threat-alerts-000001" \
  -H "Content-Type: application/json" -d '{
    "aliases": { "threat-alerts": { "is_write_index": true } }
  }' > /dev/null
echo "   ✅ threat-alerts-000001 created with alias."

echo ""
echo "=============================================="
echo "  ✅ Elasticsearch setup complete!"
echo "  🌐 Kibana:         http://localhost:5601"
echo "  🔍 Elasticsearch:  http://localhost:9200"
echo "  👤 Username:       elastic"
echo "  🔑 Password:       ${ELASTIC_PASSWORD}"
echo "=============================================="
