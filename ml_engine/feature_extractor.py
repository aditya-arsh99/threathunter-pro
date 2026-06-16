"""
=============================================================
 ThreatHunter Pro — Feature Extractor
 feature_extractor.py

 Converts raw Kafka event dicts into normalised numpy arrays
 ready for the ML models.

 NetworkFlow features (15):
   bytes_sent, bytes_recv, bytes_total, packets_sent,
   packets_recv, packets_total, duration_ms, bytes_per_sec,
   src_port_norm, dst_port_norm, protocol_tcp, protocol_udp,
   protocol_icmp, has_syn, has_rst

 WindowsEvent features (8) per timestep:
   event_id_norm, hour_of_day_norm, day_of_week_norm,
   logon_type_norm, is_admin_user, is_system_process,
   is_suspicious_process, is_external_ip
=============================================================
"""

import re
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.preprocessing import RobustScaler
import joblib
import os

from loguru import logger


# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
NETWORK_FEATURE_DIM  = 15
WINDOWS_FEATURE_DIM  = 8
WINDOWS_SEQ_LEN      = 10      # LSTM looks at last 10 events per host

# High-value Event IDs normalised to [0,1]
TRACKED_EVENT_IDS = [
    4624, 4625, 4648, 4672, 4688, 4698,
    4720, 4732, 4756, 7045, 1102
]
EVENT_ID_MAP = {eid: idx / len(TRACKED_EVENT_IDS)
                for idx, eid in enumerate(TRACKED_EVENT_IDS)}

ADMIN_USERS = {"administrator", "admin", "root", "system"}
SUSPICIOUS_PROCESS_PATTERNS = [
    r"\\temp\\", r"\\public\\", r"\\appdata\\",
    r"powershell", r"cmd\.exe", r"wscript", r"mshta",
    r"certutil", r"bitsadmin", r"regsvr32",
]

COMPILED_SUSPICIOUS = [re.compile(p, re.IGNORECASE)
                       for p in SUSPICIOUS_PROCESS_PATTERNS]


# ------------------------------------------------------------------
# Network Flow Feature Extractor
# ------------------------------------------------------------------
class NetworkFeatureExtractor:
    """
    Converts a raw network flow dict → numpy float32 array (shape: [15])
    Also fits/applies a RobustScaler for normalisation.
    """

    FEATURE_NAMES = [
        "bytes_sent", "bytes_recv", "bytes_total",
        "packets_sent", "packets_recv", "packets_total",
        "duration_ms", "bytes_per_sec",
        "src_port_norm", "dst_port_norm",
        "protocol_tcp", "protocol_udp", "protocol_icmp",
        "has_syn", "has_rst",
    ]

    def __init__(self, scaler_path: Optional[str] = None):
        self.scaler = RobustScaler()
        self.scaler_fitted = False
        if scaler_path and os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
            self.scaler_fitted = True
            logger.info(f"Loaded network scaler from {scaler_path}")

    def extract(self, event: dict) -> np.ndarray:
        """Extract raw (unscaled) feature vector from event."""
        protocol = str(event.get("protocol", "")).upper()
        flags    = [str(f).upper() for f in event.get("tcp_flags", [])]

        features = np.array([
            float(event.get("bytes_sent",    0) or 0),
            float(event.get("bytes_recv",    0) or 0),
            float(event.get("bytes_total",   0) or 0),
            float(event.get("packets_sent",  0) or 0),
            float(event.get("packets_recv",  0) or 0),
            float(event.get("packets_total", 0) or 0),
            float(event.get("duration_ms",   0) or 0),
            float(event.get("bytes_per_sec", 0) or 0),
            # Port normalised to [0,1]
            min(float(event.get("src_port",  0) or 0), 65535) / 65535.0,
            min(float(event.get("dst_port",  0) or 0), 65535) / 65535.0,
            # Protocol one-hot
            1.0 if protocol == "TCP"  else 0.0,
            1.0 if protocol == "UDP"  else 0.0,
            1.0 if protocol == "ICMP" else 0.0,
            # TCP flags
            1.0 if "SYN" in flags else 0.0,
            1.0 if "RST" in flags else 0.0,
        ], dtype=np.float32)

        return features

    def fit_transform(self, events: List[dict]) -> np.ndarray:
        """Fit scaler on training data and return scaled matrix."""
        raw = np.array([self.extract(e) for e in events], dtype=np.float32)
        # Only scale the continuous features (first 8), leave binary as-is
        scaled = raw.copy()
        scaled[:, :8] = self.scaler.fit_transform(raw[:, :8])
        self.scaler_fitted = True
        return scaled

    def transform(self, event: dict) -> np.ndarray:
        """Transform a single event using the fitted scaler."""
        raw = self.extract(event).reshape(1, -1)
        if self.scaler_fitted:
            raw[0, :8] = self.scaler.transform(raw[:, :8])[0]
        return raw[0]

    def transform_batch(self, events: List[dict]) -> np.ndarray:
        raw = np.array([self.extract(e) for e in events], dtype=np.float32)
        if self.scaler_fitted:
            raw[:, :8] = self.scaler.transform(raw[:, :8])
        return raw

    def save_scaler(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self.scaler, path)
        logger.info(f"Network scaler saved to {path}")


# ------------------------------------------------------------------
# Windows Event Feature Extractor
# ------------------------------------------------------------------
class WindowsFeatureExtractor:
    """
    Converts a raw Windows event dict → numpy float32 array (shape: [8])
    Maintains per-host event sequence buffers for LSTM input.
    """

    FEATURE_NAMES = [
        "event_id_norm",
        "hour_of_day_norm",
        "day_of_week_norm",
        "logon_type_norm",
        "is_admin_user",
        "is_system_process",
        "is_suspicious_process",
        "is_external_src_ip",
    ]

    def __init__(self, seq_len: int = WINDOWS_SEQ_LEN):
        self.seq_len = seq_len
        # host → deque of last seq_len feature vectors
        self._host_buffers: Dict[str, List[np.ndarray]] = {}

    def extract(self, event: dict) -> np.ndarray:
        """Extract single-event feature vector."""
        from datetime import datetime, timezone

        # Timestamp-based features
        ts_str = event.get("@timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            hour       = ts.hour / 23.0
            day_of_week = ts.weekday() / 6.0
        except (ValueError, AttributeError):
            hour        = 0.0
            day_of_week = 0.0

        event_id    = int(event.get("event_id", 0) or 0)
        logon_type  = int(event.get("logon_type", 0) or 0)
        user        = str(event.get("user", "")).lower()
        process     = str(event.get("process_name", "")).lower()
        src_ip      = str(event.get("src_ip", ""))

        # Is external IP (not RFC1918)
        is_external = 1.0
        if any(src_ip.startswith(prefix) for prefix in
               ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                "172.29.", "172.30.", "172.31.", "127.", "")):
            is_external = 0.0

        # Is suspicious process
        is_suspicious = 0.0
        if process:
            for pattern in COMPILED_SUSPICIOUS:
                if pattern.search(process):
                    is_suspicious = 1.0
                    break

        features = np.array([
            EVENT_ID_MAP.get(event_id, 0.5),        # event_id_norm
            hour,                                    # hour_of_day_norm
            day_of_week,                             # day_of_week_norm
            min(logon_type, 11) / 11.0,             # logon_type_norm
            1.0 if user in ADMIN_USERS else 0.0,    # is_admin_user
            1.0 if "system" in process else 0.0,    # is_system_process
            is_suspicious,                           # is_suspicious_process
            is_external,                             # is_external_src_ip
        ], dtype=np.float32)

        return features

    def get_sequence(self, event: dict) -> Optional[np.ndarray]:
        """
        Add event to host buffer and return sequence if buffer is full.
        Returns shape: [seq_len, feature_dim] or None if buffer not full yet.
        """
        host = str(event.get("computer", "unknown"))
        vec  = self.extract(event)

        if host not in self._host_buffers:
            self._host_buffers[host] = []

        self._host_buffers[host].append(vec)

        # Keep only last seq_len events
        if len(self._host_buffers[host]) > self.seq_len:
            self._host_buffers[host].pop(0)

        if len(self._host_buffers[host]) == self.seq_len:
            return np.stack(self._host_buffers[host], axis=0)  # [seq_len, 8]

        return None   # Not enough history yet

    def get_sequences_from_list(
        self, events: List[dict]
    ) -> Tuple[np.ndarray, List[int]]:
        """
        Build sequence dataset from a list of events.
        Returns (X, valid_indices) where X shape is [N, seq_len, feature_dim].
        """
        sequences = []
        valid_idx = []

        # Reset buffers for clean training
        self._host_buffers = {}

        for i, event in enumerate(events):
            seq = self.get_sequence(event)
            if seq is not None:
                sequences.append(seq)
                valid_idx.append(i)

        if not sequences:
            return np.empty((0, self.seq_len, WINDOWS_FEATURE_DIM)), []

        return np.stack(sequences, axis=0), valid_idx
