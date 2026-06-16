"""
=============================================================
 ThreatHunter Pro — Real-Time Inference Engine
 inference.py

 Runs two parallel Kafka consumer threads:
   Thread 1: Consumes network-flows
             → Autoencoder scores each flow
             → Writes scored event to Elasticsearch
             → If anomaly: publishes to threat-alerts topic

   Thread 2: Consumes windows-events
             → LSTM scores each event sequence
             → Writes scored event to Elasticsearch
             → If anomaly: publishes to threat-alerts topic

 Usage:
   python inference.py
   python inference.py --kafka localhost:29092 --es-host localhost:9200
=============================================================
"""

import argparse
import json
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import numpy as np
from loguru import logger

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

from confluent_kafka import Consumer, Producer, KafkaError
from elasticsearch import Elasticsearch, helpers

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml_engine.feature_extractor import (
    NetworkFeatureExtractor,
    WindowsFeatureExtractor,
)
from ml_engine.models.autoencoder import NetworkAutoencoder
from ml_engine.models.lstm_detector import WindowsLSTMDetector


# ------------------------------------------------------------------
# Config defaults
# ------------------------------------------------------------------
KAFKA_BOOTSTRAP = "localhost:29092"
ES_HOST         = "http://localhost:9200"
ES_USER         = "elastic"
ES_PASS         = "ThreatHunter@2024"
MODEL_DIR       = "./data/models"
SCALER_PATH     = "./data/models/network_scaler.pkl"

TOPIC_NETWORK   = "network-flows"
TOPIC_WINDOWS   = "windows-events"
TOPIC_ALERTS    = "threat-alerts"

IDX_NETWORK     = "network-flows"
IDX_WINDOWS     = "windows-events"
IDX_ALERTS      = "threat-alerts"

ES_BATCH_SIZE   = 100   # bulk index every N events


# ------------------------------------------------------------------
# Elasticsearch Helper
# ------------------------------------------------------------------
class ESWriter:
    """Batched Elasticsearch writer."""

    def __init__(self, host: str, user: str, password: str):
        self.es = Elasticsearch(
            host,
            basic_auth=(user, password),
            verify_certs=False,
            ssl_show_warn=False,
        )
        self._buffer = []
        self._lock   = threading.Lock()

        try:
            info = self.es.info()
            logger.success(f"Elasticsearch connected: {info['version']['number']}")
        except Exception as e:
            logger.error(f"Elasticsearch connection failed: {e}")
            raise

    def add(self, index: str, doc: dict):
        """Add a document to the write buffer."""
        with self._lock:
            self._buffer.append({
                "_index": index,
                "_id":    doc.get("flow_id") or doc.get("event_uid") or str(uuid.uuid4()),
                "_source": doc,
            })
            if len(self._buffer) >= ES_BATCH_SIZE:
                self._flush()

    def flush(self):
        with self._lock:
            self._flush()

    def _flush(self):
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
            self._buffer.clear()
        except Exception as e:
            logger.error(f"ES bulk write failed: {e}")
            self._buffer.clear()


# ------------------------------------------------------------------
# Alert Publisher
# ------------------------------------------------------------------
def make_alert(event: dict, score: float, severity: str, source_type: str) -> dict:
    """Build a threat alert document."""
    return {
        "@timestamp":     datetime.now(timezone.utc).isoformat(),
        "alert_id":       str(uuid.uuid4()),
        "source_type":    source_type,
        "severity":       severity,
        "anomaly_score":  round(score, 6),
        "description":    _alert_description(event, severity, source_type),
        "mitre_tactic":   event.get("mitre_tactic", "unknown"),
        "mitre_technique": event.get("mitre_technique", ""),
        "src_ip":         event.get("src_ip", ""),
        "dst_ip":         event.get("dst_ip", ""),
        "hostname":       event.get("computer", ""),
        "status":         "open",
        "raw_event":      event,
    }


def _alert_description(event: dict, severity: str, source_type: str) -> str:
    if source_type == "network":
        return (
            f"[{severity.upper()}] Anomalous network flow detected: "
            f"{event.get('src_ip','?')} → {event.get('dst_ip','?')}:"
            f"{event.get('dst_port','?')} ({event.get('protocol','?')})"
        )
    else:
        return (
            f"[{severity.upper()}] Anomalous Windows event sequence on "
            f"{event.get('computer','?')}: EventID={event.get('event_id','?')} "
            f"User={event.get('user','?')}"
        )


# ------------------------------------------------------------------
# Network Flow Consumer Thread
# ------------------------------------------------------------------
class NetworkInferenceConsumer(threading.Thread):

    def __init__(
        self,
        kafka_bootstrap: str,
        es_writer:       ESWriter,
        alert_producer:  Producer,
        model_dir:       str,
        scaler_path:     str,
    ):
        super().__init__(name="NetworkConsumer", daemon=True)
        self.kafka_bootstrap = kafka_bootstrap
        self.es_writer       = es_writer
        self.alert_producer  = alert_producer
        self._stop_event     = threading.Event()

        # Load model and feature extractor
        self.extractor = NetworkFeatureExtractor(scaler_path=scaler_path)
        self.model     = NetworkAutoencoder(model_dir=model_dir)

        if not self.model.load():
            logger.error("Network autoencoder not found. Run trainer.py first.")
            self._stop_event.set()

        self.processed = 0
        self.anomalies = 0

    def run(self):
        consumer = Consumer({
            "bootstrap.servers":  self.kafka_bootstrap,
            "group.id":           "threathunter-inference-network",
            "auto.offset.reset":  "latest",
            "enable.auto.commit": True,
        })
        consumer.subscribe([TOPIC_NETWORK])
        logger.info("🌐 Network inference consumer started.")

        try:
            while not self._stop_event.is_set():
                msg = consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error(f"Network consumer error: {msg.error()}")
                    continue

                try:
                    event = json.loads(msg.value().decode("utf-8"))
                    self._process(event)
                except Exception as e:
                    logger.debug(f"Network processing error: {e}")

        finally:
            consumer.close()
            self.es_writer.flush()
            logger.info(f"Network consumer stopped. Processed={self.processed} | Anomalies={self.anomalies}")

    def _process(self, event: dict):
        # Extract features and score
        features = self.extractor.transform(event)
        score    = self.model.score(features)
        severity = self.model.get_severity(score)
        is_anom  = self.model.is_anomaly(score)

        # Annotate event
        event["anomaly_score"] = round(score, 6)
        event["is_anomaly"]    = is_anom
        event["severity"]      = severity

        # Write to Elasticsearch
        self.es_writer.add(IDX_NETWORK, event)
        self.processed += 1

        if is_anom:
            self.anomalies += 1
            alert = make_alert(event, score, severity, "network")
            self._publish_alert(alert)

            if self.processed % 100 == 0:
                logger.warning(
                    f"🚨 Anomaly | score={score:.4f} | severity={severity} | "
                    f"{event.get('src_ip')} → {event.get('dst_ip')}:{event.get('dst_port')}"
                )

        if self.processed % 500 == 0:
            logger.info(f"Network: processed={self.processed} | anomalies={self.anomalies}")

    def _publish_alert(self, alert: dict):
        try:
            self.alert_producer.produce(
                topic=TOPIC_ALERTS,
                value=json.dumps(alert).encode("utf-8"),
                key=alert["alert_id"].encode("utf-8"),
            )
            self.alert_producer.poll(0)
        except Exception as e:
            logger.debug(f"Alert publish error: {e}")

    def stop(self):
        self._stop_event.set()


# ------------------------------------------------------------------
# Windows Event Consumer Thread
# ------------------------------------------------------------------
class WindowsInferenceConsumer(threading.Thread):

    def __init__(
        self,
        kafka_bootstrap: str,
        es_writer:       ESWriter,
        alert_producer:  Producer,
        model_dir:       str,
    ):
        super().__init__(name="WindowsConsumer", daemon=True)
        self.kafka_bootstrap = kafka_bootstrap
        self.es_writer       = es_writer
        self.alert_producer  = alert_producer
        self._stop_event     = threading.Event()

        # Load model and feature extractor
        self.extractor = WindowsFeatureExtractor(seq_len=10)
        self.model     = WindowsLSTMDetector(model_dir=model_dir)

        if not self.model.load():
            logger.error("LSTM model not found. Run trainer.py first.")
            self._stop_event.set()

        self.processed = 0
        self.anomalies = 0

    def run(self):
        consumer = Consumer({
            "bootstrap.servers":  self.kafka_bootstrap,
            "group.id":           "threathunter-inference-windows",
            "auto.offset.reset":  "latest",
            "enable.auto.commit": True,
        })
        consumer.subscribe([TOPIC_WINDOWS])
        logger.info("🪟 Windows inference consumer started.")

        try:
            while not self._stop_event.is_set():
                msg = consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() != KafkaError._PARTITION_EOF:
                        logger.error(f"Windows consumer error: {msg.error()}")
                    continue

                try:
                    event = json.loads(msg.value().decode("utf-8"))
                    self._process(event)
                except Exception as e:
                    logger.debug(f"Windows processing error: {e}")

        finally:
            consumer.close()
            self.es_writer.flush()
            logger.info(f"Windows consumer stopped. Processed={self.processed} | Anomalies={self.anomalies}")

    def _process(self, event: dict):
        # Build sequence and score if buffer is full
        sequence = self.extractor.get_sequence(event)
        self.processed += 1

        if sequence is None:
            # Not enough history yet — write unscored event to ES
            event["anomaly_score"] = None
            event["is_anomaly"]    = False
            self.es_writer.add(IDX_WINDOWS, event)
            return

        score    = self.model.score(sequence)
        severity = self.model.get_severity(score)
        is_anom  = self.model.is_anomaly(score)

        # Annotate event
        event["anomaly_score"] = round(score, 6)
        event["is_anomaly"]    = is_anom
        event["severity"]      = severity

        self.es_writer.add(IDX_WINDOWS, event)

        if is_anom:
            self.anomalies += 1
            alert = make_alert(event, score, severity, "windows")
            self._publish_alert(alert)
            logger.warning(
                f"🚨 Windows Anomaly | score={score:.4f} | severity={severity} | "
                f"host={event.get('computer')} | EventID={event.get('event_id')}"
            )

        if self.processed % 500 == 0:
            logger.info(f"Windows: processed={self.processed} | anomalies={self.anomalies}")

    def _publish_alert(self, alert: dict):
        try:
            self.alert_producer.produce(
                topic=TOPIC_ALERTS,
                value=json.dumps(alert).encode("utf-8"),
                key=alert["alert_id"].encode("utf-8"),
            )
            self.alert_producer.poll(0)
        except Exception as e:
            logger.debug(f"Alert publish error: {e}")

    def stop(self):
        self._stop_event.set()


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter Pro — Real-Time Inference Engine"
    )
    parser.add_argument("--kafka",     default=KAFKA_BOOTSTRAP)
    parser.add_argument("--es-host",   default=ES_HOST)
    parser.add_argument("--es-user",   default=ES_USER)
    parser.add_argument("--es-pass",   default=ES_PASS)
    parser.add_argument("--model-dir", default=MODEL_DIR)
    args = parser.parse_args()

    os.makedirs("logs", exist_ok=True)
    logger.add("logs/inference_{time}.log", rotation="100MB", level="INFO")

    logger.info("=" * 60)
    logger.info("  ThreatHunter Pro — Inference Engine Starting")
    logger.info("=" * 60)

    # Shared Elasticsearch writer
    es_writer = ESWriter(
        host=args.es_host,
        user=args.es_user,
        password=args.es_pass,
    )

    # Shared alert Kafka producer
    alert_producer = Producer({
        "bootstrap.servers": args.kafka,
        "client.id":         "threathunter-alert-producer",
    })

    # Create and start consumer threads
    net_consumer = NetworkInferenceConsumer(
        kafka_bootstrap = args.kafka,
        es_writer       = es_writer,
        alert_producer  = alert_producer,
        model_dir       = args.model_dir,
        scaler_path     = os.path.join(args.model_dir, "network_scaler.pkl"),
    )
    win_consumer = WindowsInferenceConsumer(
        kafka_bootstrap = args.kafka,
        es_writer       = es_writer,
        alert_producer  = alert_producer,
        model_dir       = args.model_dir,
    )

    net_consumer.start()
    win_consumer.start()

    logger.success("✅ Inference engine running. Press Ctrl+C to stop.")
    logger.info("   Waiting for events from Kafka...")

    try:
        while True:
            time.sleep(5)
            # Periodic stats
            logger.info(
                f"📊 Stats | Network: {net_consumer.processed} processed, "
                f"{net_consumer.anomalies} anomalies | "
                f"Windows: {win_consumer.processed} processed, "
                f"{win_consumer.anomalies} anomalies"
            )
            es_writer.flush()

    except KeyboardInterrupt:
        logger.info("Shutting down inference engine...")
        net_consumer.stop()
        win_consumer.stop()
        net_consumer.join(timeout=5)
        win_consumer.join(timeout=5)
        es_writer.flush()
        alert_producer.flush(timeout=5)
        logger.success("Inference engine stopped cleanly.")


if __name__ == "__main__":
    main()
