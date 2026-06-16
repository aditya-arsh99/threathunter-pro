"""
=============================================================
 ThreatHunter Pro — Model Training Pipeline
 trainer.py

 Workflow:
   1. Consume events from Kafka (network-flows + windows-events)
      OR generate synthetic training data if Kafka is empty
   2. Split into normal / attack subsets (uses heuristics)
   3. Extract features
   4. Train Autoencoder on normal network flows
   5. Train LSTM AE on normal Windows event sequences
   6. Save models + scalers to ./data/models/

 Usage:
   python trainer.py                        ← consume from Kafka
   python trainer.py --synthetic 10000     ← use synthetic data
   python trainer.py --synthetic 10000 --epochs 30
=============================================================
"""

import argparse
import json
import os
import sys
import random
import time
from typing import List, Tuple

import numpy as np
from loguru import logger

# Suppress TF output before import
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

from confluent_kafka import Consumer, KafkaError, TopicPartition

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml_engine.feature_extractor import NetworkFeatureExtractor, WindowsFeatureExtractor
from ml_engine.models.autoencoder import NetworkAutoencoder
from ml_engine.models.lstm_detector import WindowsLSTMDetector


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
MODEL_DIR   = "./data/models"
SCALER_PATH = "./data/models/network_scaler.pkl"
KAFKA_BOOTSTRAP = "localhost:29092"


# ------------------------------------------------------------------
# Kafka Data Collector
# ------------------------------------------------------------------
class KafkaDataCollector:
    """Consumes all available messages from a Kafka topic."""

    def __init__(self, bootstrap_servers: str = KAFKA_BOOTSTRAP):
        self.bootstrap_servers = bootstrap_servers

    def collect(self, topic: str, max_messages: int = 50000, timeout_s: float = 10.0) -> List[dict]:
        """
        Reads all available messages from a topic from the beginning.
        Returns list of parsed event dicts.
        """
        logger.info(f"📥 Collecting from Kafka topic: {topic}")

        consumer = Consumer({
            "bootstrap.servers":  self.bootstrap_servers,
            "group.id":           f"threathunter-trainer-{int(time.time())}",
            "auto.offset.reset":  "earliest",
            "enable.auto.commit": False,
        })

        consumer.subscribe([topic])
        events     = []
        idle_since = time.time()

        try:
            while len(events) < max_messages:
                msg = consumer.poll(timeout=1.0)

                if msg is None:
                    if time.time() - idle_since > timeout_s:
                        logger.info(f"No more messages for {timeout_s}s. Stopping.")
                        break
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        break
                    logger.error(f"Kafka error: {msg.error()}")
                    break

                idle_since = time.time()
                try:
                    event = json.loads(msg.value().decode("utf-8"))
                    events.append(event)
                except json.JSONDecodeError:
                    pass

                if len(events) % 1000 == 0:
                    logger.info(f"   Collected {len(events)} events...")

        finally:
            consumer.close()

        logger.info(f"✅ Collected {len(events)} events from {topic}")
        return events


# ------------------------------------------------------------------
# Synthetic Data Generator (for training without Kafka data)
# ------------------------------------------------------------------
def generate_synthetic_network_events(n: int = 10000) -> List[dict]:
    """Generate synthetic network flow events for training."""
    logger.info(f"🎲 Generating {n} synthetic network events...")
    events = []
    protocols = ["TCP", "UDP", "ICMP"]

    for _ in range(n):
        is_attack = random.random() < 0.15   # 15% attack traffic

        if is_attack:
            # Attack-like: port scan (tiny bytes, many ports) or exfil (huge bytes)
            attack_type = random.choice(["scan", "exfil", "c2"])
            if attack_type == "scan":
                event = {
                    "bytes_sent": random.randint(40, 100),
                    "bytes_recv": random.randint(0, 60),
                    "bytes_total": random.randint(40, 160),
                    "packets_sent": 1,
                    "packets_recv": random.randint(0, 1),
                    "packets_total": random.randint(1, 2),
                    "duration_ms": random.uniform(0.1, 5),
                    "bytes_per_sec": random.uniform(10, 500),
                    "src_port": random.randint(49152, 65535),
                    "dst_port": random.randint(1, 65535),
                    "protocol": "TCP",
                    "tcp_flags": ["SYN"],
                }
            elif attack_type == "exfil":
                event = {
                    "bytes_sent": random.randint(5_000_000, 50_000_000),
                    "bytes_recv": random.randint(100, 1000),
                    "bytes_total": random.randint(5_000_000, 50_001_000),
                    "packets_sent": random.randint(5000, 50000),
                    "packets_recv": random.randint(5, 20),
                    "packets_total": random.randint(5005, 50020),
                    "duration_ms": random.uniform(10000, 120000),
                    "bytes_per_sec": random.uniform(100000, 5000000),
                    "src_port": random.randint(49152, 65535),
                    "dst_port": random.choice([21, 22, 443]),
                    "protocol": "TCP",
                    "tcp_flags": ["SYN", "ACK", "PSH"],
                }
            else:  # c2
                event = {
                    "bytes_sent": random.randint(64, 256),
                    "bytes_recv": random.randint(64, 256),
                    "bytes_total": random.randint(128, 512),
                    "packets_sent": random.randint(1, 3),
                    "packets_recv": random.randint(1, 3),
                    "packets_total": random.randint(2, 6),
                    "duration_ms": random.uniform(50, 200),
                    "bytes_per_sec": random.uniform(50, 500),
                    "src_port": random.randint(49152, 65535),
                    "dst_port": random.choice([4444, 8080, 1337]),
                    "protocol": "TCP",
                    "tcp_flags": ["SYN", "ACK", "PSH"],
                }
            event["_is_attack"] = True

        else:
            # Normal traffic
            protocol = random.choice(protocols)
            event = {
                "bytes_sent": random.randint(300, 10000),
                "bytes_recv": random.randint(500, 50000),
                "bytes_total": random.randint(800, 60000),
                "packets_sent": random.randint(3, 30),
                "packets_recv": random.randint(5, 50),
                "packets_total": random.randint(8, 80),
                "duration_ms": random.uniform(10, 800),
                "bytes_per_sec": random.uniform(1000, 100000),
                "src_port": random.randint(49152, 65535),
                "dst_port": random.choice([80, 443, 53, 8080, 8443]),
                "protocol": protocol,
                "tcp_flags": ["SYN", "ACK"] if protocol == "TCP" else [],
                "_is_attack": False,
            }
        events.append(event)

    return events


def generate_synthetic_windows_events(n: int = 5000) -> List[dict]:
    """Generate synthetic Windows events for training."""
    logger.info(f"🎲 Generating {n} synthetic Windows events...")
    from datetime import datetime, timezone

    events    = []
    hosts     = ["DC01", "WKSTN-001", "WKSTN-002", "SRV-FILE01", "SRV-WEB01"]
    normal_ids   = [4624, 4688, 4672]
    attack_ids   = [4625, 4648, 4698, 4720, 4732, 7045, 1102]
    logon_types  = [2, 3, 10]

    for i in range(n):
        is_attack = random.random() < 0.12
        event_id  = random.choice(attack_ids if is_attack else normal_ids)
        host      = random.choice(hosts)

        from datetime import timedelta
        hour = random.choice(range(9, 18)) if not is_attack else random.choice([0, 1, 2, 3, 22, 23])
        ts   = datetime.now(timezone.utc).replace(hour=hour) - timedelta(days=random.randint(0, 30))

        event = {
            "@timestamp":    ts.isoformat(),
            "event_id":      event_id,
            "computer":      host,
            "user":          random.choice(["john.doe", "SYSTEM", "Administrator", "jane.smith"]),
            "logon_type":    random.choice(logon_types) if event_id in [4624, 4625] else 0,
            "process_name":  random.choice([
                "C:\\Windows\\System32\\svchost.exe",
                "C:\\Windows\\explorer.exe",
                "C:\\Windows\\System32\\cmd.exe" if is_attack else "C:\\Program Files\\notepad.exe",
            ]),
            "src_ip":        random.choice(["192.168.1.10", "10.0.0.5"])
                             if not is_attack else random.choice(["185.220.101.45", "194.165.16.72"]),
            "_is_attack":    is_attack,
        }
        events.append(event)

    return events


# ------------------------------------------------------------------
# Data Splitter
# ------------------------------------------------------------------
def split_normal_attack(
    events: List[dict],
    attack_key: str = "_is_attack",
) -> Tuple[List[dict], List[dict]]:
    """
    Split events into normal and attack subsets.
    Uses _is_attack flag (from synthetic) or heuristics (from Kafka).
    """
    if any(attack_key in e for e in events):
        # Synthetic data — use the flag
        normal = [e for e in events if not e.get(attack_key, False)]
        attack = [e for e in events if e.get(attack_key, False)]
    else:
        # Real Kafka data — use heuristics
        normal, attack = [], []
        for e in events:
            score = 0
            # Network heuristics
            if e.get("bytes_sent", 0) > 1_000_000:    score += 2  # large upload
            if e.get("duration_ms", 0) < 5:            score += 1  # very short
            if e.get("dst_port") in [4444, 1337]:      score += 3  # suspicious port
            # Windows heuristics
            if e.get("event_id") in [4625, 7045, 1102]: score += 2
            if score >= 2:
                attack.append(e)
            else:
                normal.append(e)

    logger.info(f"Split: normal={len(normal)}, attack={len(attack)}")
    return normal, attack


# ------------------------------------------------------------------
# Main Training Pipeline
# ------------------------------------------------------------------
def train_network_model(events: List[dict], epochs: int):
    """Train the Autoencoder on network flow events."""
    logger.info("=" * 60)
    logger.info("PHASE: Training Network Flow Autoencoder")
    logger.info("=" * 60)

    normal_events, _ = split_normal_attack(events)

    if len(normal_events) < 100:
        logger.error(f"Not enough normal events for training (got {len(normal_events)}, need 100+)")
        return

    # Feature extraction
    extractor = NetworkFeatureExtractor(scaler_path=SCALER_PATH)
    X = extractor.fit_transform(normal_events)
    extractor.save_scaler(SCALER_PATH)
    logger.info(f"Network feature matrix: {X.shape}")

    # Train/val split (80/20)
    split     = int(len(X) * 0.8)
    X_train   = X[:split]
    X_val     = X[split:]

    # Train
    model = NetworkAutoencoder(model_dir=MODEL_DIR)
    model.train(X_train, X_val=X_val, epochs=epochs)
    logger.success("✅ Network Autoencoder training complete!")


def train_windows_model(events: List[dict], epochs: int):
    """Train the LSTM Autoencoder on Windows event sequences."""
    logger.info("=" * 60)
    logger.info("PHASE: Training Windows LSTM Autoencoder")
    logger.info("=" * 60)

    normal_events, _ = split_normal_attack(events)

    if len(normal_events) < 50:
        logger.error(f"Not enough normal Windows events (got {len(normal_events)}, need 50+)")
        return

    # Feature extraction — builds sequences per host
    extractor = WindowsFeatureExtractor(seq_len=10)
    X, _      = extractor.get_sequences_from_list(normal_events)

    if len(X) < 20:
        logger.warning(f"Only {len(X)} sequences built. Need more events per host.")
        logger.warning("Training on available data...")

    logger.info(f"Windows sequence matrix: {X.shape}")

    # Train/val split
    split   = int(len(X) * 0.8)
    X_train = X[:split]
    X_val   = X[split:] if split < len(X) else None

    # Train
    model = WindowsLSTMDetector(model_dir=MODEL_DIR)
    model.train(X_train, X_val=X_val, epochs=epochs)
    logger.success("✅ Windows LSTM training complete!")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter Pro — ML Training Pipeline"
    )
    parser.add_argument(
        "--synthetic", type=int, default=0,
        help="Generate N synthetic events for training (skip Kafka). Recommended: 10000"
    )
    parser.add_argument(
        "--epochs", type=int, default=30,
        help="Training epochs (default: 30)"
    )
    parser.add_argument(
        "--kafka", default=KAFKA_BOOTSTRAP,
        help=f"Kafka bootstrap server (default: {KAFKA_BOOTSTRAP})"
    )
    parser.add_argument(
        "--model-dir", default=MODEL_DIR,
        help=f"Model output directory (default: {MODEL_DIR})"
    )
    args = parser.parse_args()

    os.makedirs("logs", exist_ok=True)
    logger.add("logs/trainer_{time}.log", rotation="50MB", level="INFO")
    logger.add(sys.stderr, level="INFO")

    logger.info("=" * 60)
    logger.info("  ThreatHunter Pro — ML Training Pipeline")
    logger.info("=" * 60)

    if args.synthetic > 0:
        # Use synthetic data
        logger.info(f"Using SYNTHETIC data mode ({args.synthetic} events)")
        net_events = generate_synthetic_network_events(args.synthetic)
        win_events = generate_synthetic_windows_events(args.synthetic // 2)
    else:
        # Consume from Kafka
        logger.info("Using KAFKA data mode")
        collector  = KafkaDataCollector(bootstrap_servers=args.kafka)
        net_events = collector.collect("network-flows",  max_messages=50000)
        win_events = collector.collect("windows-events", max_messages=50000)

        if len(net_events) < 100:
            logger.warning(
                f"Only {len(net_events)} network events in Kafka. "
                "Run mock_generator.py first, or use --synthetic 10000"
            )
        if len(win_events) < 50:
            logger.warning(f"Only {len(win_events)} Windows events in Kafka.")

    # Train both models
    train_network_model(net_events, epochs=args.epochs)
    train_windows_model(win_events, epochs=args.epochs)

    logger.success("=" * 60)
    logger.success("  ✅ All models trained and saved!")
    logger.success(f"  📁 Models saved to: {args.model_dir}")
    logger.success("  🚀 Run inference.py to start real-time scoring")
    logger.success("=" * 60)


if __name__ == "__main__":
    main()
