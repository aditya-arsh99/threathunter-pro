"""
=============================================================
 ThreatHunter Pro — Shared Kafka Producer
 kafka_producer.py

 Used by both pcap_ingestor.py and evtx_ingestor.py.
 Handles:
   - Connection to Kafka broker
   - JSON serialization
   - Delivery confirmation callbacks
   - Retry logic
=============================================================
"""

import json
import time
from datetime import datetime, timezone
from typing import Optional

from confluent_kafka import Producer, KafkaException
from loguru import logger


# ------------------------------------------------------------------
# Topics
# ------------------------------------------------------------------
TOPIC_NETWORK_FLOWS  = "network-flows"
TOPIC_WINDOWS_EVENTS = "windows-events"
TOPIC_ALERTS         = "threat-alerts"


class ThreatHunterProducer:
    """
    Wrapper around confluent_kafka.Producer.
    Provides simple publish() method with automatic retries.
    """

    def __init__(
        self,
        bootstrap_servers: str = "localhost:29092",
        client_id: str = "threathunter-ingestor",
        retries: int = 3,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.retries = retries
        self._producer = self._create_producer(bootstrap_servers, client_id)
        self._sent     = 0
        self._failed   = 0

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _create_producer(self, bootstrap_servers: str, client_id: str) -> Producer:
        conf = {
            "bootstrap.servers":            bootstrap_servers,
            "client.id":                    client_id,
            "acks":                         "all",          # wait for all replicas
            "retries":                      5,
            "retry.backoff.ms":             500,
            "compression.type":             "lz4",          # compress for throughput
            "batch.size":                   65536,          # 64KB batches
            "linger.ms":                    10,             # wait 10ms to batch
            "queue.buffering.max.messages": 100000,
            "queue.buffering.max.kbytes":   65536,
        }
        logger.info(f"Connecting to Kafka at {bootstrap_servers}...")
        producer = Producer(conf)
        logger.success("Kafka producer ready.")
        return producer

    def _delivery_callback(self, err, msg):
        """Called by Kafka for every message after delivery attempt."""
        if err:
            logger.error(f"❌ Delivery failed | topic={msg.topic()} | error={err}")
            self._failed += 1
        else:
            self._sent += 1
            if self._sent % 1000 == 0:
                logger.info(f"📨 {self._sent} messages delivered to Kafka")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def publish(
        self,
        topic:   str,
        payload: dict,
        key:     Optional[str] = None,
    ) -> bool:
        """
        Serialize payload to JSON and send to Kafka topic.
        Returns True on success, False on failure.
        """
        # Inject ingest timestamp if not present
        if "@timestamp" not in payload:
            payload["@timestamp"] = datetime.now(timezone.utc).isoformat()

        message_bytes = json.dumps(payload, default=str).encode("utf-8")
        key_bytes     = key.encode("utf-8") if key else None

        for attempt in range(1, self.retries + 1):
            try:
                self._producer.produce(
                    topic    = topic,
                    value    = message_bytes,
                    key      = key_bytes,
                    callback = self._delivery_callback,
                )
                self._producer.poll(0)   # trigger callbacks without blocking
                return True

            except BufferError:
                logger.warning(f"Kafka buffer full — flushing (attempt {attempt})...")
                self._producer.flush(timeout=5)
            except KafkaException as e:
                logger.error(f"Kafka error on attempt {attempt}: {e}")
                time.sleep(0.5 * attempt)

        return False

    def flush(self, timeout: float = 30.0):
        """Flush all buffered messages. Call before exiting."""
        logger.info("Flushing Kafka producer buffer...")
        remaining = self._producer.flush(timeout=timeout)
        if remaining > 0:
            logger.warning(f"{remaining} messages were NOT delivered before timeout.")
        logger.success(f"Flush complete. Sent={self._sent} | Failed={self._failed}")

    def stats(self) -> dict:
        return {"sent": self._sent, "failed": self._failed}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.flush()
