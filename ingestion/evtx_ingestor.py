"""
=============================================================
 ThreatHunter Pro — Windows EVTX Ingestor
 evtx_ingestor.py

 Reads Windows .evtx log files, parses each event,
 normalises the fields and pushes to Kafka topic: windows-events

 Covers high-value Event IDs mapped to MITRE ATT&CK:
   4624  Successful logon         → T1078 Valid Accounts
   4625  Failed logon             → T1110 Brute Force
   4648  Explicit credential use  → T1134 Token Manipulation
   4688  Process creation         → T1059 Command & Scripting
   4698  Scheduled task created   → T1053 Scheduled Task
   4720  User account created     → T1136 Create Account
   4732  Member added to group    → T1098 Account Manipulation
   4756  Member added to univ grp → T1098 Account Manipulation
   7045  New service installed    → T1543 Create/Modify Service
   1102  Audit log cleared        → T1070 Indicator Removal

 Usage:
   python evtx_ingestor.py --file path/to/Security.evtx
   python evtx_ingestor.py --file path/to/Security.evtx --dry-run
   python evtx_ingestor.py --file path/to/Security.evtx --event-ids 4624,4625
=============================================================
"""

import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional
from xml.etree import ElementTree as ET

from loguru import logger

try:
    from Evtx.Evtx import Evtx
except ImportError:
    logger.error("python-evtx not installed. Run: pip install python-evtx lxml")
    sys.exit(1)

from kafka_producer import ThreatHunterProducer, TOPIC_WINDOWS_EVENTS


# ------------------------------------------------------------------
# MITRE ATT&CK mapping for key Event IDs
# ------------------------------------------------------------------
MITRE_MAP: Dict[int, Dict] = {
    4624: {"tactic": "Initial Access",        "technique": "T1078", "technique_name": "Valid Accounts",              "severity": "low"},
    4625: {"tactic": "Credential Access",     "technique": "T1110", "technique_name": "Brute Force",                 "severity": "medium"},
    4648: {"tactic": "Privilege Escalation",  "technique": "T1134", "technique_name": "Access Token Manipulation",   "severity": "medium"},
    4688: {"tactic": "Execution",             "technique": "T1059", "technique_name": "Command and Scripting Interpreter", "severity": "low"},
    4698: {"tactic": "Persistence",           "technique": "T1053", "technique_name": "Scheduled Task/Job",          "severity": "high"},
    4720: {"tactic": "Persistence",           "technique": "T1136", "technique_name": "Create Account",              "severity": "high"},
    4732: {"tactic": "Privilege Escalation",  "technique": "T1098", "technique_name": "Account Manipulation",        "severity": "high"},
    4756: {"tactic": "Privilege Escalation",  "technique": "T1098", "technique_name": "Account Manipulation",        "severity": "high"},
    7045: {"tactic": "Persistence",           "technique": "T1543", "technique_name": "Create or Modify System Process", "severity": "critical"},
    1102: {"tactic": "Defense Evasion",       "technique": "T1070", "technique_name": "Indicator Removal on Host",   "severity": "critical"},
}

# Logon type descriptions
LOGON_TYPES = {
    "2":  "Interactive",
    "3":  "Network",
    "4":  "Batch",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

# XML namespace used in EVTX
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


# ------------------------------------------------------------------
# EVTX Parser
# ------------------------------------------------------------------
class EvtxParser:
    """Parses a single .evtx record into a normalised dict."""

    @staticmethod
    def get(node, tag: str, ns: str = NS) -> Optional[str]:
        """Safe XML element text getter."""
        el = node.find(f"{{{ns}}}{tag}")
        return el.text.strip() if el is not None and el.text else None

    @staticmethod
    def get_data(event_data, name: str) -> Optional[str]:
        """Extract named Data element from EventData."""
        for child in event_data:
            if child.get("Name") == name and child.text:
                return child.text.strip()
        return None

    def parse_record(self, xml_str: str) -> Optional[dict]:
        """
        Parse one EVTX record XML string into a normalised event dict.
        Returns None if the event should be skipped.
        """
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.debug(f"XML parse error: {e}")
            return None

        system = root.find(f"{{{NS}}}System")
        if system is None:
            return None

        # --- System fields ---
        event_id_el = system.find(f"{{{NS}}}EventID")
        if event_id_el is None:
            return None

        try:
            event_id = int(event_id_el.text.strip())
        except (ValueError, AttributeError):
            return None

        # TimeCreated
        time_created = system.find(f"{{{NS}}}TimeCreated")
        ts_str = time_created.get("SystemTime") if time_created is not None else None
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.now(timezone.utc)
        except ValueError:
            ts = datetime.now(timezone.utc)

        computer_el = system.find(f"{{{NS}}}Computer")
        computer    = computer_el.text.strip() if computer_el is not None and computer_el.text else "unknown"

        channel_el  = system.find(f"{{{NS}}}Channel")
        channel     = channel_el.text.strip() if channel_el is not None and channel_el.text else "unknown"

        # --- EventData fields (vary by Event ID) ---
        event_data = root.find(f"{{{NS}}}EventData")
        ed         = {}
        if event_data is not None:
            for child in event_data:
                name  = child.get("Name", "")
                value = child.text.strip() if child.text else ""
                if name:
                    ed[name] = value

        # --- Build normalised event ---
        mitre       = MITRE_MAP.get(event_id, {})
        logon_type  = ed.get("LogonType", "")

        event = {
            "@timestamp":        ts.isoformat(),
            "event_id":          event_id,
            "event_id_keyword":  str(event_id),
            "channel":           channel,
            "computer":          computer,
            # Account info
            "user":              ed.get("SubjectUserName") or ed.get("TargetUserName", ""),
            "domain":            ed.get("SubjectDomainName") or ed.get("TargetDomainName", ""),
            "logon_type":        int(logon_type) if logon_type.isdigit() else None,
            "logon_type_name":   LOGON_TYPES.get(logon_type, logon_type),
            # Process info
            "process_name":      ed.get("NewProcessName") or ed.get("ProcessName", ""),
            "parent_process":    ed.get("ParentProcessName", ""),
            "command_line":      ed.get("CommandLine", ""),
            "process_id":        ed.get("NewProcessId", ""),
            # Network info
            "src_ip":            ed.get("IpAddress", ""),
            "src_port":          ed.get("IpPort", ""),
            # Service/Task info
            "service_name":      ed.get("ServiceName", ""),
            "task_name":         ed.get("TaskName", ""),
            # Group info
            "group_name":        ed.get("GroupName", ""),
            "member_name":       ed.get("MemberName", ""),
            # Description
            "description":       self._describe(event_id, ed),
            # MITRE ATT&CK
            "mitre_tactic":      mitre.get("tactic", "unknown"),
            "mitre_technique":   mitre.get("technique", ""),
            "mitre_technique_name": mitre.get("technique_name", ""),
            # Severity baseline (ML engine will override)
            "severity":          mitre.get("severity", "low"),
            # ML placeholders
            "anomaly_score":     None,
            "is_anomaly":        False,
            # Source
            "source":            "evtx",
        }

        # Generate stable event ID
        event["event_uid"] = hashlib.md5(
            f"{event['@timestamp']}{event_id}{computer}{event['user']}".encode()
        ).hexdigest()

        return event

    def _describe(self, event_id: int, ed: dict) -> str:
        """Human-readable description for key event IDs."""
        desc_map = {
            4624: lambda: f"Successful logon by {ed.get('TargetUserName','?')} ({LOGON_TYPES.get(ed.get('LogonType',''),'?')} logon) from {ed.get('IpAddress','-')}",
            4625: lambda: f"FAILED logon for {ed.get('TargetUserName','?')} from {ed.get('IpAddress','-')} (type: {LOGON_TYPES.get(ed.get('LogonType',''),'?')})",
            4648: lambda: f"Explicit credential logon by {ed.get('SubjectUserName','?')} targeting {ed.get('TargetUserName','?')}",
            4688: lambda: f"Process created: {ed.get('NewProcessName','?')} by {ed.get('SubjectUserName','?')}",
            4698: lambda: f"Scheduled task created: {ed.get('TaskName','?')} by {ed.get('SubjectUserName','?')}",
            4720: lambda: f"User account created: {ed.get('TargetUserName','?')} by {ed.get('SubjectUserName','?')}",
            4732: lambda: f"Member {ed.get('MemberName','?')} added to group {ed.get('GroupName','?')}",
            7045: lambda: f"New service installed: {ed.get('ServiceName','?')}",
            1102: lambda: f"Audit log cleared by {ed.get('SubjectUserName','?')}",
        }
        fn = desc_map.get(event_id)
        return fn() if fn else f"Windows Event {event_id}"


# ------------------------------------------------------------------
# EVTX Ingestor
# ------------------------------------------------------------------
class EvtxIngestor:

    def __init__(
        self,
        producer: Optional[ThreatHunterProducer],
        dry_run: bool = False,
        filter_event_ids: Optional[List[int]] = None,
    ):
        self.producer         = producer
        self.dry_run          = dry_run
        self.filter_event_ids = set(filter_event_ids) if filter_event_ids else None
        self.parser           = EvtxParser()
        self._total     = 0
        self._sent      = 0
        self._skipped   = 0
        self._errors    = 0

    def process_file(self, evtx_path: str):
        if not os.path.exists(evtx_path):
            logger.error(f"File not found: {evtx_path}")
            sys.exit(1)

        logger.info(f"📂 Reading EVTX: {evtx_path}")

        try:
            with Evtx(evtx_path) as evtx_file:
                for record in evtx_file.records():
                    self._total += 1
                    try:
                        xml_str = record.xml()
                        self._process_record(xml_str)
                    except Exception as e:
                        logger.debug(f"Record read error: {e}")
                        self._errors += 1

                    if self._total % 1000 == 0:
                        logger.info(f"   Processed {self._total} records...")

        except Exception as e:
            logger.error(f"Failed to read EVTX file: {e}")
            sys.exit(1)

        logger.success(
            f"✅ Done | Total={self._total} | Sent={self._sent} | "
            f"Skipped={self._skipped} | Errors={self._errors}"
        )

    def _process_record(self, xml_str: str):
        try:
            event = self.parser.parse_record(xml_str)
            if event is None:
                self._skipped += 1
                return

            # Apply event ID filter if specified
            if self.filter_event_ids and event["event_id"] not in self.filter_event_ids:
                self._skipped += 1
                return

            self._emit(event)

        except Exception as e:
            logger.debug(f"Error processing record: {e}")
            self._errors += 1

    def _emit(self, event: dict):
        self._sent += 1

        if self.dry_run:
            import json
            logger.info(f"[DRY RUN] EventID={event['event_id']} | {event['description']}")
            return

        self.producer.publish(
            topic   = TOPIC_WINDOWS_EVENTS,
            payload = event,
            key     = event.get("event_uid"),
        )


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter Pro — Windows EVTX Ingestor"
    )
    parser.add_argument("--file", "-f", required=True, help="Path to .evtx file")
    parser.add_argument("--kafka", default="localhost:29092", help="Kafka bootstrap server")
    parser.add_argument("--dry-run", action="store_true", help="Parse without sending to Kafka")
    parser.add_argument(
        "--event-ids",
        help="Comma-separated Event IDs to filter (e.g. 4624,4625,4688). Default: all.",
        default=None,
    )
    args = parser.parse_args()

    logger.add(
        "logs/evtx_ingestor_{time}.log",
        rotation="50 MB",
        retention="7 days",
        level="INFO",
    )

    filter_ids = None
    if args.event_ids:
        try:
            filter_ids = [int(x.strip()) for x in args.event_ids.split(",")]
            logger.info(f"🔍 Filtering for Event IDs: {filter_ids}")
        except ValueError:
            logger.error("Invalid --event-ids format. Use comma-separated integers.")
            sys.exit(1)

    if args.dry_run:
        logger.info("🔍 DRY RUN mode — no messages will be sent to Kafka")
        ingestor = EvtxIngestor(producer=None, dry_run=True, filter_event_ids=filter_ids)
        ingestor.process_file(args.file)
    else:
        with ThreatHunterProducer(bootstrap_servers=args.kafka) as producer:
            ingestor = EvtxIngestor(producer=producer, filter_event_ids=filter_ids)
            ingestor.process_file(args.file)


if __name__ == "__main__":
    main()
