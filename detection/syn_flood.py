"""
detection/syn_flood.py

Heuristic SYN flood / abnormal SYN rate detector.

Detects unusually high rates of TCP SYN packets that may indicate a SYN flood
attack. This detector tracks SYN packets both globally and per (src, dst) pair
within a sliding time window.

IMPORTANT: This detector LABELS conservatively as "possible SYN flood /
abnormal SYN activity" rather than asserting a definitive attack, because
the packet metadata captured does not include full TCP stateful session
tables to verify connection completion rates.

This is a HEURISTIC. Legitimate bursty traffic (e.g., many clients connecting
to a server simultaneously) can trigger it. Alerts should be treated as
investigation leads.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Tuple

from config import DetectionConfig
from core.models import PacketRecord, Severity, ThreatAlert
from detection.base import BaseDetector


def _is_syn_only(tcp_flags: Optional[str]) -> bool:
    if not tcp_flags:
        return False
    flags = tcp_flags.strip()
    return "S" in flags and "A" not in flags


class SynFloodDetector(BaseDetector):
    """Possible SYN Flood / Abnormal SYN Activity detector - Rule NET-004."""

    rule_id = "NET-004"
    rule_name = "Possible SYN Flood / Abnormal SYN Activity"

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        # Global SYN tracker: deque of timestamps
        self._global_syn: Deque[float] = deque()
        # Per (src, dst) pair tracker: key -> deque of timestamps
        self._pair_syn: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        # Last alert times: key -> timestamp
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._alert_cooldown = 5.0

    def observe(self, record: PacketRecord) -> Optional[ThreatAlert]:
        # Only process SYN packets (not SYN-ACK)
        if record.protocol.value != "TCP" or not _is_syn_only(record.tcp_flags):
            return None

        now = record.timestamp
        key = (record.src_ip, record.dst_ip)

        with self._lock:
            # Track globally
            self._global_syn.append(now)
            global_cutoff = now - self.config.syn_flood_window_seconds
            while self._global_syn and self._global_syn[0] < global_cutoff:
                self._global_syn.popleft()

            # Track per pair
            self._pair_syn[key].append(now)
            pair_cutoff = now - self.config.syn_flood_window_seconds
            while self._pair_syn[key] and self._pair_syn[key][0] < pair_cutoff:
                self._pair_syn[key].popleft()

            global_count = len(self._global_syn)
            pair_count = len(self._pair_syn[key])

            threshold = self.config.syn_flood_packet_threshold
            if global_count < threshold and pair_count < threshold:
                return None

            last = self._last_alert.get(key)
            if last is not None and now - last < self._alert_cooldown:
                return None
            self._last_alert[key] = now

            # Determine which threshold triggered
            if pair_count >= threshold:
                detail = (
                    f"Observed {pair_count} SYN packets from {record.src_ip} "
                    f"to {record.dst_ip} within {self.config.syn_flood_window_seconds:.0f}s "
                    "(possible SYN flood / abnormal SYN activity)."
                )
            else:
                detail = (
                    f"Observed {global_count} SYN packets within "
                    f"{self.config.syn_flood_window_seconds:.0f}s with unusually low "
                    "completion/response activity (possible SYN flood / abnormal SYN activity)."
                )

            return ThreatAlert(
                timestamp=now,
                rule=self.rule_id,
                severity=Severity.HIGH,
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                detail=detail,
                evidence_count=max(global_count, pair_count),
            )

    def reset(self) -> None:
        with self._lock:
            self._global_syn.clear()
            self._pair_syn.clear()
            self._last_alert.clear()

    def cleanup_state(self, now: float) -> None:
        """Purge expired state entries."""
        with self._lock:
            cutoff = now - self.config.syn_flood_window_seconds
            while self._global_syn and self._global_syn[0] < cutoff:
                self._global_syn.popleft()
            for key in list(self._pair_syn.keys()):
                events = self._pair_syn[key]
                while events and events[0] < cutoff:
                    events.popleft()
                if not events:
                    del self._pair_syn[key]
            expired = [k for k, ts in self._last_alert.items() if now - ts > self._alert_cooldown * 2]
            for k in expired:
                del self._last_alert[k]
