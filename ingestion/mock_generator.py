"""
=============================================================
 ThreatHunter Pro — Mock Data Generator
 mock_generator.py

 Generates synthetic security events directly into Kafka
 so you can test the full pipeline without real PCAP/EVTX files.

 Simulates:
   - Normal network traffic (HTTP, DNS, HTTPS)
   - Attack patterns (port scans, brute force, C2 beaconing)
   - Normal Windows logon events
   - Suspicious Windows events (new user, service install, log clear)

 Usage:
   python mock_generator.py --events 5000 --mode mixed
   python mock_generator.py --events 1000 --mode attack
   python mock_generator.py --events 500  --mode normal
=============================================================
"""

import argparse
import random
import time
from datetime import datetime, timezone, timedelta
from typing import List

from faker import Faker
from loguru import logger

from kafka_producer import ThreatHunterProducer, TOPIC_NETWORK_FLOWS, TOPIC_WINDOWS_EVENTS

fake = Faker()
random.seed(42)


# ------------------------------------------------------------------
# Internal IP pools
# ------------------------------------------------------------------
INTERNAL_SUBNETS = [
    [f"192.168.1.{i}"  for i in range(1, 50)],
    [f"10.0.0.{i}"     for i in range(1, 30)],
    [f"172.16.0.{i}"   for i in range(1, 20)],
]
INTERNAL_IPS = [ip for subnet in INTERNAL_SUBNETS for ip in subnet]

EXTERNAL_IPS  = [fake.ipv4_public() for _ in range(100)]

# Known malicious-looking IPs for attack simulation
ATTACKER_IPS  = [
    "185.220.101.45",  "194.165.16.72",  "45.33.32.156",
    "198.98.56.14",    "91.108.4.183",   "77.247.181.162",
    "23.129.64.131",   "171.25.193.20",
]

COMMON_PORTS  = [80, 443, 53, 22, 3389, 445, 8080, 8443, 3306, 5432]
HIGH_PORTS    = list(range(49152, 65535))

WINDOWS_USERS = ["SYSTEM", "Administrator", "john.doe", "jane.smith",
                  "svc_backup", "svc_sql", "helpdesk01"]
WINDOWS_HOSTS = ["DC01", "WKSTN-001", "WKSTN-002", "SRV-FILE01",
                  "SRV-WEB01", "LAPTOP-HR01"]
PROCESSES     = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\powershell.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
]
SUSPICIOUS_PROCESSES = [
    "C:\\Users\\Public\\malware.exe",
    "C:\\Temp\\payload.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\wscript.exe",
    "C:\\Windows\\System32\\mshta.exe",
]


# ------------------------------------------------------------------
# Network Flow Generators
# ------------------------------------------------------------------
class NetworkFlowGenerator:

    def normal_http(self) -> dict:
        return {
            "src_ip":        random.choice(INTERNAL_IPS),
            "dst_ip":        random.choice(EXTERNAL_IPS),
            "src_port":      random.randint(49152, 65535),
            "dst_port":      random.choice([80, 443, 8080, 8443]),
            "protocol":      "TCP",
            "bytes_sent":    random.randint(300, 5000),
            "bytes_recv":    random.randint(1000, 50000),
            "bytes_total":   0,
            "packets_sent":  random.randint(3, 20),
            "packets_recv":  random.randint(5, 40),
            "packets_total": 0,
            "duration_ms":   random.uniform(10, 500),
            "bytes_per_sec": random.uniform(1000, 50000),
            "tcp_flags":     ["SYN", "ACK"],
            "source":        "mock",
        }

    def normal_dns(self) -> dict:
        return {
            "src_ip":        random.choice(INTERNAL_IPS),
            "dst_ip":        random.choice(["8.8.8.8", "8.8.4.4", "1.1.1.1"]),
            "src_port":      random.randint(49152, 65535),
            "dst_port":      53,
            "protocol":      "UDP",
            "bytes_sent":    random.randint(50, 150),
            "bytes_recv":    random.randint(80, 400),
            "bytes_total":   0,
            "packets_sent":  1,
            "packets_recv":  1,
            "packets_total": 2,
            "duration_ms":   random.uniform(1, 50),
            "bytes_per_sec": random.uniform(100, 1000),
            "tcp_flags":     [],
            "source":        "mock",
        }

    def port_scan(self) -> List[dict]:
        """Simulate a port scan — same src, same dst, many ports."""
        attacker = random.choice(ATTACKER_IPS)
        victim   = random.choice(INTERNAL_IPS)
        events   = []
        for port in random.sample(range(1, 10000), 50):
            events.append({
                "src_ip":        attacker,
                "dst_ip":        victim,
                "src_port":      random.randint(49152, 65535),
                "dst_port":      port,
                "protocol":      "TCP",
                "bytes_sent":    random.randint(40, 80),
                "bytes_recv":    random.randint(0, 80),
                "bytes_total":   0,
                "packets_sent":  1,
                "packets_recv":  random.randint(0, 1),
                "packets_total": random.randint(1, 2),
                "duration_ms":   random.uniform(0.1, 5),
                "bytes_per_sec": random.uniform(10, 500),
                "tcp_flags":     ["SYN"],
                "source":        "mock",
            })
        return events

    def c2_beacon(self) -> dict:
        """Simulate C2 beaconing — regular small packets to external IP."""
        return {
            "src_ip":        random.choice(INTERNAL_IPS),
            "dst_ip":        random.choice(ATTACKER_IPS),
            "src_port":      random.randint(49152, 65535),
            "dst_port":      random.choice([443, 80, 8443, 4444]),
            "protocol":      "TCP",
            "bytes_sent":    random.randint(64, 256),     # small — beaconing
            "bytes_recv":    random.randint(64, 256),
            "bytes_total":   0,
            "packets_sent":  random.randint(1, 3),
            "packets_recv":  random.randint(1, 3),
            "packets_total": random.randint(2, 6),
            "duration_ms":   random.uniform(50, 200),
            "bytes_per_sec": random.uniform(50, 500),
            "tcp_flags":     ["SYN", "ACK", "PSH"],
            "source":        "mock",
        }

    def data_exfil(self) -> dict:
        """Simulate data exfiltration — large bytes_sent to external."""
        return {
            "src_ip":        random.choice(INTERNAL_IPS),
            "dst_ip":        random.choice(ATTACKER_IPS),
            "src_port":      random.randint(49152, 65535),
            "dst_port":      random.choice([443, 21, 22]),
            "protocol":      "TCP",
            "bytes_sent":    random.randint(5_000_000, 50_000_000),   # huge
            "bytes_recv":    random.randint(1000, 5000),
            "bytes_total":   0,
            "packets_sent":  random.randint(5000, 50000),
            "packets_recv":  random.randint(10, 100),
            "packets_total": 0,
            "duration_ms":   random.uniform(10000, 120000),
            "bytes_per_sec": random.uniform(100000, 5000000),
            "tcp_flags":     ["SYN", "ACK", "PSH", "FIN"],
            "source":        "mock",
        }

    def _finalise(self, event: dict) -> dict:
        event["bytes_total"]   = event["bytes_sent"] + event["bytes_recv"]
        event["packets_total"] = event.get("packets_total") or \
                                  event["packets_sent"] + event["packets_recv"]
        event["@timestamp"]    = datetime.now(timezone.utc).isoformat()
        event["anomaly_score"] = None
        event["is_anomaly"]    = False
        event["severity"]      = "none"

        import hashlib
        event["flow_id"] = hashlib.md5(
            f"{event['src_ip']}{event['dst_ip']}{event['src_port']}"
            f"{event['dst_port']}{event['@timestamp']}".encode()
        ).hexdigest()
        return event


# ------------------------------------------------------------------
# Windows Event Generators
# ------------------------------------------------------------------
class WindowsEventGenerator:

    def successful_logon(self) -> dict:
        user = random.choice(WINDOWS_USERS)
        return {
            "event_id":             4624,
            "event_id_keyword":     "4624",
            "channel":              "Security",
            "computer":             random.choice(WINDOWS_HOSTS),
            "user":                 user,
            "domain":               "CORP",
            "logon_type":           random.choice([2, 3, 10]),
            "logon_type_name":      random.choice(["Interactive", "Network", "RemoteInteractive"]),
            "process_name":         "",
            "parent_process":       "",
            "command_line":         "",
            "src_ip":               random.choice(INTERNAL_IPS),
            "src_port":             str(random.randint(49152, 65535)),
            "description":          f"Successful logon by {user}",
            "mitre_tactic":         "Initial Access",
            "mitre_technique":      "T1078",
            "mitre_technique_name": "Valid Accounts",
            "severity":             "low",
            "anomaly_score":        None,
            "is_anomaly":           False,
            "source":               "mock",
        }

    def failed_logon(self) -> dict:
        user = random.choice(WINDOWS_USERS)
        return {
            "event_id":             4625,
            "event_id_keyword":     "4625",
            "channel":              "Security",
            "computer":             random.choice(WINDOWS_HOSTS),
            "user":                 user,
            "domain":               "CORP",
            "logon_type":           3,
            "logon_type_name":      "Network",
            "process_name":         "",
            "parent_process":       "",
            "command_line":         "",
            "src_ip":               random.choice(ATTACKER_IPS),
            "src_port":             str(random.randint(49152, 65535)),
            "description":          f"FAILED logon for {user}",
            "mitre_tactic":         "Credential Access",
            "mitre_technique":      "T1110",
            "mitre_technique_name": "Brute Force",
            "severity":             "medium",
            "anomaly_score":        None,
            "is_anomaly":           False,
            "source":               "mock",
        }

    def process_creation(self, suspicious: bool = False) -> dict:
        proc = random.choice(SUSPICIOUS_PROCESSES if suspicious else PROCESSES)
        return {
            "event_id":             4688,
            "event_id_keyword":     "4688",
            "channel":              "Security",
            "computer":             random.choice(WINDOWS_HOSTS),
            "user":                 random.choice(WINDOWS_USERS),
            "domain":               "CORP",
            "logon_type":           None,
            "logon_type_name":      "",
            "process_name":         proc,
            "parent_process":       random.choice(PROCESSES),
            "command_line":         f"{proc} {fake.bs()}",
            "src_ip":               "",
            "src_port":             "",
            "description":          f"Process created: {proc}",
            "mitre_tactic":         "Execution",
            "mitre_technique":      "T1059",
            "mitre_technique_name": "Command and Scripting Interpreter",
            "severity":             "high" if suspicious else "low",
            "anomaly_score":        None,
            "is_anomaly":           False,
            "source":               "mock",
        }

    def new_user_created(self) -> dict:
        new_user = f"svc_{fake.user_name()}"
        return {
            "event_id":             4720,
            "event_id_keyword":     "4720",
            "channel":              "Security",
            "computer":             "DC01",
            "user":                 "Administrator",
            "domain":               "CORP",
            "logon_type":           None,
            "logon_type_name":      "",
            "process_name":         "",
            "parent_process":       "",
            "command_line":         "",
            "src_ip":               "",
            "src_port":             "",
            "description":          f"User account created: {new_user}",
            "mitre_tactic":         "Persistence",
            "mitre_technique":      "T1136",
            "mitre_technique_name": "Create Account",
            "severity":             "high",
            "anomaly_score":        None,
            "is_anomaly":           False,
            "source":               "mock",
        }

    def audit_log_cleared(self) -> dict:
        return {
            "event_id":             1102,
            "event_id_keyword":     "1102",
            "channel":              "Security",
            "computer":             random.choice(WINDOWS_HOSTS),
            "user":                 random.choice(["Administrator", "SYSTEM"]),
            "domain":               "CORP",
            "logon_type":           None,
            "logon_type_name":      "",
            "process_name":         "C:\\Windows\\System32\\wevtutil.exe",
            "parent_process":       "C:\\Windows\\System32\\cmd.exe",
            "command_line":         "wevtutil cl Security",
            "src_ip":               "",
            "src_port":             "",
            "description":          "⚠️ Security audit log was cleared!",
            "mitre_tactic":         "Defense Evasion",
            "mitre_technique":      "T1070",
            "mitre_technique_name": "Indicator Removal on Host",
            "severity":             "critical",
            "anomaly_score":        None,
            "is_anomaly":           False,
            "source":               "mock",
        }

    def _finalise(self, event: dict) -> dict:
        import hashlib
        event["@timestamp"] = datetime.now(timezone.utc).isoformat()
        event["event_uid"]  = hashlib.md5(
            f"{event['@timestamp']}{event['event_id']}{event['computer']}{event['user']}".encode()
        ).hexdigest()
        return event


# ------------------------------------------------------------------
# Main Generator
# ------------------------------------------------------------------
class MockDataGenerator:

    def __init__(self, producer: ThreatHunterProducer, mode: str = "mixed"):
        self.producer = producer
        self.mode     = mode
        self.net_gen  = NetworkFlowGenerator()
        self.win_gen  = WindowsEventGenerator()

    def generate(self, total_events: int, events_per_second: int = 200):
        logger.info(f"🎲 Generating {total_events} mock events (mode={self.mode})...")
        sent = 0
        batch_size = min(events_per_second, 500)

        while sent < total_events:
            batch = min(batch_size, total_events - sent)
            for _ in range(batch):
                self._send_one()
                sent += 1

            self.producer._producer.poll(0)
            if sent % 1000 == 0:
                logger.info(f"   Generated {sent}/{total_events} events...")
            time.sleep(1.0 / events_per_second)

        logger.success(f"✅ Mock generation complete. Total={sent}")

    def _send_one(self):
        # Distribution based on mode
        if self.mode == "normal":
            self._send_normal()
        elif self.mode == "attack":
            self._send_attack()
        else:  # mixed
            r = random.random()
            if r < 0.70:
                self._send_normal()
            elif r < 0.85:
                self._send_mild_suspicious()
            else:
                self._send_attack()

    def _send_normal(self):
        r = random.random()
        if r < 0.5:
            # Normal network
            fn = random.choice([self.net_gen.normal_http, self.net_gen.normal_dns])
            event = self.net_gen._finalise(fn())
            self.producer.publish(TOPIC_NETWORK_FLOWS, event, key=event["flow_id"])
        else:
            # Normal Windows
            event = self.win_gen._finalise(self.win_gen.successful_logon())
            self.producer.publish(TOPIC_WINDOWS_EVENTS, event, key=event["event_uid"])

    def _send_mild_suspicious(self):
        r = random.random()
        if r < 0.5:
            event = self.win_gen._finalise(self.win_gen.failed_logon())
            self.producer.publish(TOPIC_WINDOWS_EVENTS, event, key=event["event_uid"])
        else:
            event = self.win_gen._finalise(self.win_gen.process_creation(suspicious=True))
            self.producer.publish(TOPIC_WINDOWS_EVENTS, event, key=event["event_uid"])

    def _send_attack(self):
        attack_type = random.choice(["scan", "c2", "exfil", "brute_force",
                                     "new_user", "log_clear"])
        if attack_type == "scan":
            for event in self.net_gen.port_scan():
                ev = self.net_gen._finalise(event)
                self.producer.publish(TOPIC_NETWORK_FLOWS, ev, key=ev["flow_id"])

        elif attack_type == "c2":
            event = self.net_gen._finalise(self.net_gen.c2_beacon())
            self.producer.publish(TOPIC_NETWORK_FLOWS, event, key=event["flow_id"])

        elif attack_type == "exfil":
            event = self.net_gen._finalise(self.net_gen.data_exfil())
            self.producer.publish(TOPIC_NETWORK_FLOWS, event, key=event["flow_id"])

        elif attack_type == "brute_force":
            for _ in range(random.randint(10, 30)):
                event = self.win_gen._finalise(self.win_gen.failed_logon())
                self.producer.publish(TOPIC_WINDOWS_EVENTS, event, key=event["event_uid"])

        elif attack_type == "new_user":
            event = self.win_gen._finalise(self.win_gen.new_user_created())
            self.producer.publish(TOPIC_WINDOWS_EVENTS, event, key=event["event_uid"])

        elif attack_type == "log_clear":
            event = self.win_gen._finalise(self.win_gen.audit_log_cleared())
            self.producer.publish(TOPIC_WINDOWS_EVENTS, event, key=event["event_uid"])


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter Pro — Mock Data Generator"
    )
    parser.add_argument("--events", type=int, default=2000,
                        help="Total events to generate (default: 2000)")
    parser.add_argument("--mode",   default="mixed",
                        choices=["normal", "attack", "mixed"],
                        help="Traffic mode (default: mixed)")
    parser.add_argument("--kafka",  default="localhost:29092",
                        help="Kafka bootstrap server")
    parser.add_argument("--eps",    type=int, default=200,
                        help="Events per second (default: 200)")
    args = parser.parse_args()

    logger.add("logs/mock_generator_{time}.log", rotation="10 MB", level="INFO")
    os.makedirs("logs", exist_ok=True)

    with ThreatHunterProducer(bootstrap_servers=args.kafka, client_id="threathunter-mock") as producer:
        gen = MockDataGenerator(producer=producer, mode=args.mode)
        gen.generate(total_events=args.events, events_per_second=args.eps)


if __name__ == "__main__":
    import os
    main()
