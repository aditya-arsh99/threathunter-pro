"""
=============================================================
 ThreatHunter Pro — Alert Engine
 alert_engine/alerter.py

 Consumes from Kafka `threat-alerts` topic and:
   1. Deduplicates alerts using Redis
      (same src_ip + event_type within 60s = one alert)
   2. Rate limits per source IP
      (max 10 alerts/min per IP)
   3. Escalates severity
      (repeated anomalies from same source → escalate)
   4. Enriches alert with context
      (port category, known bad IP check, MITRE context)
   5. Writes final alert to Elasticsearch threat-alerts index

 Also fixes the inference.py gap — inference publishes to
 Kafka topic, this engine is the proper consumer that
 writes to Elasticsearch.

 Usage:
   python alerter.py
   python alerter.py --kafka localhost:29092
=============================================================
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import redis
from loguru import logger
from confluent_kafka import Consumer, KafkaError
from elasticsearch import Elasticsearch, helpers

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
KAFKA_BOOTSTRAP  = "localhost:29092"
TOPIC_ALERTS     = "threat-alerts"
IDX_ALERTS       = "threat-alerts"

ES_HOST          = "http://localhost:9200"
ES_USER          = "elastic"
ES_PASS          = "ThreatHunter@2024"

REDIS_HOST       = "localhost"
REDIS_PORT       = 6379

DEDUP_TTL_S      = 60        # suppress duplicate alerts for 60s
RATE_LIMIT_MAX   = 10        # max alerts per IP per minute
RATE_LIMIT_TTL_S = 60        # rate limit window
ESCALATION_COUNT = 5         # hits before escalating severity
ES_BATCH_SIZE    = 20        # bulk write every N alerts

# ------------------------------------------------------------------
# Known bad IP ranges (simplified — in production use threat intel feed)
# ------------------------------------------------------------------
KNOWN_BAD_IPS = {
    "185.220.101.45", "194.165.16.72", "45.33.32.156",
    "198.98.56.14",   "91.108.4.183",  "77.247.181.162",
    "23.129.64.131",  "171.25.193.20",
}

# Well-known port categories
PORT_CATEGORIES = {
    21:   "FTP",       22:  "SSH",        23:   "Telnet",
    25:   "SMTP",      53:  "DNS",        80:   "HTTP",
    110:  "POP3",      143: "IMAP",       443:  "HTTPS",
    445:  "SMB",       3306:"MySQL",      3389: "RDP",
    5432: "PostgreSQL",6379:"Redis",      8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017:"MongoDB",   4444: "Metasploit",
    1337: "Hacker",    9200: "Elasticsearch",
}

SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


# ------------------------------------------------------------------
# Redis Helper
# ------------------------------------------------------------------
class RedisClient:
    def __init__(self, host: str = REDIS_HOST, port: int = REDIS_PORT):
        self.r = redis.Redis(host=host, port=port, db=0, decode_responses=True)
        try:
            self.r.ping()
            logger.success("Redis connected.")
        except redis.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}")
            raise

    def is_duplicate(self, dedup_key: str) -> bool:
        """Returns True if this alert was already seen within TTL."""
        return self.r.exists(f"dedup:{dedup_key}") > 0

    def mark_seen(self, dedup_key: str):
        """Mark alert as seen for DEDUP_TTL_S seconds."""
        self.r.setex(f"dedup:{dedup_key}", DEDUP_TTL_S, "1")

    def is_rate_limited(self, ip: str) -> bool:
        """Returns True if IP has exceeded RATE_LIMIT_MAX alerts/min."""
        key   = f"ratelimit:{ip}"
        count = self.r.incr(key)
        if count == 1:
            self.r.expire(key, RATE_LIMIT_TTL_S)
        return count > RATE_LIMIT_MAX

    def get_hit_count(self, ip: str) -> int:
        """Returns how many times this IP has triggered alerts."""
        key = f"hits:{ip}"
        count = self.r.incr(key)
        self.r.expire(key, 3600)   # reset hit count after 1 hour
        return count


# ------------------------------------------------------------------
# Elasticsearch Writer
# ------------------------------------------------------------------
class ESAlertWriter:
    def __init__(self, host: str, user: str, password: str):
        self.es = Elasticsearch(
            host,
            basic_auth=(user, password),
            verify_certs=False,
            ssl_show_warn=False,
        )
        self._buffer = []
        try:
            self.es.info()
            logger.success("Elasticsearch connected (alert writer).")
        except Exception as e:
            logger.error(f"Elasticsearch connection failed: {e}")
            raise

    def add(self, doc: dict):
        self._buffer.append({
            "_index": IDX_ALERTS,
            "_id":    doc.get("alert_id"),
            "_source": doc,
        })
        if len(self._buffer) >= ES_BATCH_SIZE:
            self.flush()

    def flush(self):
        if not self._buffer:
            return
        try:
            ok, errors = helpers.bulk(
                self.es,
                self._buffer,
                raise_on_error=False,
                stats_only=False,
            )
            if errors:
                logger.warning(f"ES bulk errors: {len(errors)}")
            else:
                logger.debug(f"Indexed {len(self._buffer)} alerts to ES")
            self._buffer.clear()
        except Exception as e:
            logger.error(f"ES bulk write failed: {e}")
            self._buffer.clear()


# ------------------------------------------------------------------
# Alert Enricher
# ------------------------------------------------------------------
class AlertEnricher:
    """Adds context to raw alerts before storage."""

    def enrich(self, alert: dict, hit_count: int) -> dict:
        alert = alert.copy()

        # Port category
        dst_port = alert.get("dst_port")
        if dst_port:
            try:
                alert["dst_port_category"] = PORT_CATEGORIES.get(
                    int(dst_port), "Unknown"
                )
            except (ValueError, TypeError):
                alert["dst_port_category"] = "Unknown"

        # Known bad IP flag
        src_ip = alert.get("src_ip", "")
        dst_ip = alert.get("dst_ip", "")
        alert["src_ip_known_bad"] = src_ip in KNOWN_BAD_IPS
        alert["dst_ip_known_bad"] = dst_ip in KNOWN_BAD_IPS

        # Severity escalation based on repeat hits
        current_severity = alert.get("severity", "low")
        alert["severity"]       = self._maybe_escalate(current_severity, hit_count)
        alert["hit_count"]      = hit_count
        alert["was_escalated"]  = alert["severity"] != current_severity

        # Processing timestamp
        alert["processed_at"]   = datetime.now(timezone.utc).isoformat()
        alert["status"]         = "open"

        # Risk score (0-100) combining anomaly score + severity + known bad
        alert["risk_score"]     = self._compute_risk_score(alert)

        return alert

    def _maybe_escalate(self, severity: str, hit_count: int) -> str:
        """Escalate severity if same source keeps triggering."""
        if hit_count < ESCALATION_COUNT:
            return severity
        idx = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 1
        new_idx = min(idx + 1, len(SEVERITY_ORDER) - 1)
        escalated = SEVERITY_ORDER[new_idx]
        if escalated != severity:
            logger.warning(f"⬆️  Severity escalated: {severity} → {escalated} (hits={hit_count})")
        return escalated

    def _compute_risk_score(self, alert: dict) -> int:
        """Compute 0-100 risk score."""
        score = 0

        # Base from severity
        sev_scores = {"none": 0, "low": 20, "medium": 40, "high": 70, "critical": 90}
        score += sev_scores.get(alert.get("severity", "low"), 20)

        # Anomaly score contribution
        anomaly = float(alert.get("anomaly_score") or 0)
        score   += min(int(anomaly * 10), 10)

        # Known bad IP bonus
        if alert.get("src_ip_known_bad") or alert.get("dst_ip_known_bad"):
            score += 15

        # Suspicious port bonus
        suspicious_ports = {4444, 1337, 31337, 9001}
        try:
            if int(alert.get("dst_port", 0)) in suspicious_ports:
                score += 10
        except (ValueError, TypeError):
            pass

        return min(score, 100)


# ------------------------------------------------------------------
# Dedup Key Builder
# ------------------------------------------------------------------
def build_dedup_key(alert: dict) -> str:
    """
    Build a dedup key from the most identifying fields.
    Same src_ip + event_type + dst_port within TTL = duplicate.
    """
    src_ip     = alert.get("src_ip", "")
    source_type = alert.get("source_type", "")
    dst_port   = str(alert.get("dst_port", ""))
    event_id   = str(alert.get("raw_event", {}).get("event_id", ""))
    hostname   = alert.get("hostname", "")

    key_str = f"{src_ip}:{source_type}:{dst_port}:{event_id}:{hostname}"
    return hashlib.md5(key_str.encode()).hexdigest()


# ------------------------------------------------------------------
# Alert Engine
# ------------------------------------------------------------------
class AlertEngine:

    def __init__(
        self,
        kafka_bootstrap: str = KAFKA_BOOTSTRAP,
        es_host:         str = ES_HOST,
        es_user:         str = ES_USER,
        es_pass:         str = ES_PASS,
        redis_host:      str = REDIS_HOST,
        redis_port:      int = REDIS_PORT,
    ):
        self.redis    = RedisClient(host=redis_host, port=redis_port)
        self.es       = ESAlertWriter(host=es_host, user=es_user, password=es_pass)
        self.enricher = AlertEnricher()

        self.consumer = Consumer({
            "bootstrap.servers":  kafka_bootstrap,
            "group.id":           "threathunter-alert-engine",
            "auto.offset.reset":  "earliest",
            "enable.auto.commit": True,
        })
        self.consumer.subscribe([TOPIC_ALERTS])

        # Stats
        self.total_received  = 0
        self.total_processed = 0
        self.total_deduped   = 0
        self.total_rate_ltd  = 0
        self.total_escalated = 0

    def run(self):
        logger.info("🚨 Alert Engine started. Consuming from threat-alerts...")
        try:
            while True:
                msg = self.consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error(f"Kafka error: {msg.error()}")
                    continue

                try:
                    alert = json.loads(msg.value().decode("utf-8"))
                    self._process(alert)
                except Exception as e:
                    logger.debug(f"Alert processing error: {e}")

        except KeyboardInterrupt:
            logger.info("Alert engine stopping...")
        finally:
            self.consumer.close()
            self.es.flush()
            self._log_stats()

    def _process(self, alert: dict):
        self.total_received += 1

        src_ip    = alert.get("src_ip", "unknown")
        dedup_key = build_dedup_key(alert)

        # --- 1. Deduplication ---
        if self.redis.is_duplicate(dedup_key):
            self.total_deduped += 1
            logger.debug(f"Deduped alert from {src_ip}")
            return
        self.redis.mark_seen(dedup_key)

        # --- 2. Rate limiting ---
        if self.redis.is_rate_limited(src_ip):
            self.total_rate_ltd += 1
            logger.debug(f"Rate limited: {src_ip}")
            return

        # --- 3. Get hit count for escalation ---
        hit_count = self.redis.get_hit_count(src_ip)

        # --- 4. Enrich alert ---
        enriched = self.enricher.enrich(alert, hit_count)

        # --- 5. Write to Elasticsearch ---
        self.es.add(enriched)
        self.total_processed += 1

        if enriched.get("was_escalated"):
            self.total_escalated += 1

        # Log high/critical alerts
        if enriched.get("severity") in ("high", "critical"):
            logger.warning(
                f"🚨 [{enriched['severity'].upper()}] "
                f"risk={enriched['risk_score']} | "
                f"{enriched.get('source_type')} | "
                f"{src_ip} → {enriched.get('dst_ip','')} | "
                f"{enriched.get('description','')[:80]}"
            )

        if self.total_received % 50 == 0:
            self._log_stats()

    def _log_stats(self):
        logger.info(
            f"📊 Alert Engine | received={self.total_received} | "
            f"processed={self.total_processed} | "
            f"deduped={self.total_deduped} | "
            f"rate_limited={self.total_rate_ltd} | "
            f"escalated={self.total_escalated}"
        )


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter Pro — Alert Engine"
    )
    parser.add_argument("--kafka",      default=KAFKA_BOOTSTRAP)
    parser.add_argument("--es-host",    default=ES_HOST)
    parser.add_argument("--es-user",    default=ES_USER)
    parser.add_argument("--es-pass",    default=ES_PASS)
    parser.add_argument("--redis-host", default=REDIS_HOST)
    parser.add_argument("--redis-port", type=int, default=REDIS_PORT)
    args = parser.parse_args()

    os.makedirs("logs", exist_ok=True)
    logger.add("logs/alerter_{time}.log", rotation="50MB", level="INFO")

    engine = AlertEngine(
        kafka_bootstrap = args.kafka,
        es_host         = args.es_host,
        es_user         = args.es_user,
        es_pass         = args.es_pass,
        redis_host      = args.redis_host,
        redis_port      = args.redis_port,
    )
    engine.run()


if __name__ == "__main__":
    main()
