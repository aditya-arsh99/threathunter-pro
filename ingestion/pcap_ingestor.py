"""
=============================================================
 ThreatHunter Pro — PCAP Ingestor
 pcap_ingestor.py

 Reads .pcap / .pcapng files, reconstructs network flows,
 extracts features and pushes each flow as a JSON event
 to the Kafka topic: network-flows

 Flow = aggregation of packets sharing the same
        (src_ip, dst_ip, src_port, dst_port, protocol)

 Usage:
   python pcap_ingestor.py --file path/to/capture.pcap
   python pcap_ingestor.py --file path/to/capture.pcap --dry-run
=============================================================
"""

import argparse
import hashlib
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from loguru import logger

# Scapy — suppress startup warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, Raw

from kafka_producer import ThreatHunterProducer, TOPIC_NETWORK_FLOWS


# ------------------------------------------------------------------
# TCP flag decoder
# ------------------------------------------------------------------
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

def decode_tcp_flags(flags_int: int) -> List[str]:
    flag_str = ""
    if flags_int & 0x01: flag_str += "F"
    if flags_int & 0x02: flag_str += "S"
    if flags_int & 0x04: flag_str += "R"
    if flags_int & 0x08: flag_str += "P"
    if flags_int & 0x10: flag_str += "A"
    if flags_int & 0x20: flag_str += "U"
    return [TCP_FLAGS[f] for f in flag_str if f in TCP_FLAGS]


# ------------------------------------------------------------------
# Flow key and accumulator
# ------------------------------------------------------------------
class FlowKey:
    __slots__ = ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")

    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip   = src_ip
        self.dst_ip   = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

    def __hash__(self):
        return hash((self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol))

    def __eq__(self, other):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol) == \
               (other.src_ip, other.dst_ip, other.src_port, other.dst_port, other.protocol)


class FlowAccumulator:
    """Accumulates packet-level data into a single flow record."""

    def __init__(self, key: FlowKey, first_ts: float):
        self.key          = key
        self.first_ts     = first_ts
        self.last_ts      = first_ts
        self.bytes_fwd    = 0
        self.bytes_bwd    = 0
        self.packets_fwd  = 0
        self.packets_bwd  = 0
        self.tcp_flags    = set()
        self.payload_lens = []

    def add_packet(self, ts: float, size: int, is_forward: bool, tcp_flags=None):
        self.last_ts = max(self.last_ts, ts)
        if is_forward:
            self.bytes_fwd   += size
            self.packets_fwd += 1
        else:
            self.bytes_bwd   += size
            self.packets_bwd += 1
        if tcp_flags:
            self.tcp_flags.update(tcp_flags)
        self.payload_lens.append(size)

    def to_event(self) -> dict:
        duration_ms = (self.last_ts - self.first_ts) * 1000
        total_bytes   = self.bytes_fwd + self.bytes_bwd
        total_packets = self.packets_fwd + self.packets_bwd

        # Bytes-per-second rate
        duration_s = max((self.last_ts - self.first_ts), 0.001)
        bps = total_bytes / duration_s

        # Flow fingerprint as unique ID
        flow_id = hashlib.md5(
            f"{self.key.src_ip}{self.key.dst_ip}"
            f"{self.key.src_port}{self.key.dst_port}"
            f"{self.key.protocol}{self.first_ts}".encode()
        ).hexdigest()

        return {
            "flow_id":       flow_id,
            "@timestamp":    datetime.fromtimestamp(self.first_ts, tz=timezone.utc).isoformat(),
            "src_ip":        self.key.src_ip,
            "dst_ip":        self.key.dst_ip,
            "src_port":      self.key.src_port,
            "dst_port":      self.key.dst_port,
            "protocol":      self.key.protocol,
            "bytes_sent":    self.bytes_fwd,
            "bytes_recv":    self.bytes_bwd,
            "bytes_total":   total_bytes,
            "packets_sent":  self.packets_fwd,
            "packets_recv":  self.packets_bwd,
            "packets_total": total_packets,
            "duration_ms":   round(duration_ms, 3),
            "bytes_per_sec": round(bps, 2),
            "tcp_flags":     list(self.tcp_flags),
            # ML features (will be scored by ml_engine)
            "anomaly_score": None,
            "is_anomaly":    False,
            "severity":      "none",
            "source":        "pcap",
        }


# ------------------------------------------------------------------
# PCAP Ingestor
# ------------------------------------------------------------------
class PcapIngestor:

    def __init__(
        self,
        producer: ThreatHunterProducer,
        dry_run: bool = False,
        flow_timeout_s: float = 60.0,
    ):
        self.producer       = producer
        self.dry_run        = dry_run
        self.flow_timeout_s = flow_timeout_s
        self._flows: Dict[FlowKey, FlowAccumulator] = {}
        self._total_packets  = 0
        self._total_flows    = 0
        self._skipped        = 0

    def process_file(self, pcap_path: str):
        if not os.path.exists(pcap_path):
            logger.error(f"File not found: {pcap_path}")
            sys.exit(1)

        logger.info(f"📂 Reading PCAP: {pcap_path}")
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            logger.error(f"Failed to read PCAP: {e}")
            sys.exit(1)

        logger.info(f"📦 {len(packets)} packets loaded. Building flows...")

        for pkt in packets:
            self._process_packet(pkt)

        # Flush all remaining flows
        self._flush_all_flows()

        logger.success(
            f"✅ Done | Packets={self._total_packets} | "
            f"Flows={self._total_flows} | Skipped={self._skipped}"
        )

    def _process_packet(self, pkt):
        self._total_packets += 1

        # Only process IP packets
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            self._skipped += 1
            return

        try:
            ip_layer  = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            src_ip    = str(ip_layer.src)
            dst_ip    = str(ip_layer.dst)
            ts        = float(pkt.time)
            pkt_size  = len(pkt)

            # Layer 4
            src_port, dst_port, protocol, tcp_flags = 0, 0, "OTHER", None

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port  = tcp.sport
                dst_port  = tcp.dport
                protocol  = "TCP"
                tcp_flags = decode_tcp_flags(int(tcp.flags))

            elif pkt.haslayer(UDP):
                udp      = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                protocol = "UDP"

            elif pkt.haslayer(ICMP):
                protocol = "ICMP"

            key = FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)

            # Create or update flow
            if key not in self._flows:
                self._flows[key] = FlowAccumulator(key, ts)

            self._flows[key].add_packet(ts, pkt_size, is_forward=True, tcp_flags=tcp_flags)

            # Check if any flows have timed out → emit them
            self._maybe_flush_timed_out(ts)

        except Exception as e:
            logger.warning(f"Error processing packet: {e}")
            self._skipped += 1

    def _maybe_flush_timed_out(self, current_ts: float):
        """Emit flows that have been idle longer than flow_timeout_s."""
        timed_out = [
            key for key, flow in self._flows.items()
            if (current_ts - flow.last_ts) > self.flow_timeout_s
        ]
        for key in timed_out:
            self._emit_flow(self._flows.pop(key))

    def _flush_all_flows(self):
        """Emit all remaining open flows at end of file."""
        logger.info(f"Flushing {len(self._flows)} remaining flows...")
        for flow in self._flows.values():
            self._emit_flow(flow)
        self._flows.clear()

    def _emit_flow(self, flow: FlowAccumulator):
        event = flow.to_event()
        self._total_flows += 1

        if self.dry_run:
            import json
            logger.debug(f"[DRY RUN] {json.dumps(event, indent=2)}")
            return

        self.producer.publish(
            topic   = TOPIC_NETWORK_FLOWS,
            payload = event,
            key     = event["flow_id"],
        )


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter Pro — PCAP Ingestor"
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        help="Path to .pcap or .pcapng file"
    )
    parser.add_argument(
        "--kafka",
        default="localhost:29092",
        help="Kafka bootstrap server (default: localhost:29092)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and print flows without sending to Kafka"
    )
    parser.add_argument(
        "--flow-timeout",
        type=float,
        default=60.0,
        help="Seconds of inactivity before a flow is emitted (default: 60)"
    )
    args = parser.parse_args()

    logger.add(
        "logs/pcap_ingestor_{time}.log",
        rotation="50 MB",
        retention="7 days",
        level="INFO",
    )

    if args.dry_run:
        logger.info("🔍 DRY RUN mode — no messages will be sent to Kafka")
        producer = None
        ingestor = PcapIngestor(producer=None, dry_run=True, flow_timeout_s=args.flow_timeout)
        ingestor.process_file(args.file)
    else:
        with ThreatHunterProducer(bootstrap_servers=args.kafka) as producer:
            ingestor = PcapIngestor(producer=producer, flow_timeout_s=args.flow_timeout)
            ingestor.process_file(args.file)
            producer.flush()


if __name__ == "__main__":
    main()
