"""
detection/traffic_spike.py

Heuristic traffic spike detector.

Detects sudden abnormal increases in traffic volume by comparing recent
packet rates against a rolling baseline. This helps identify potential
DDoS-like bursts or unusual network activity.

The detector builds a baseline over time and alerts when the current
rate significantly exceeds the baseline. It includes warm-up logic to
avoid false positives during startup.

This is a HEURISTIC. Legitimate traffic bursts (e.g., backup jobs,
large file transfers) can trigger it. Alerts should be treated as
investigation leads.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Deque, Optional, Tuple

from config import DetectionConfig
from core.models import PacketRecord, Severity, ThreatAlert
from detection.base import BaseDetector


class TrafficSpikeDetector(BaseDetector):
    """Traffic Spike detector - Rule NET-005."""

    rule_id = "NET-005"
    rule_name = "Traffic Spike"

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        # Track packet timestamps for rate calculation
        self._packets: Deque[float] = deque()
        # Track (timestamp, bytes) for bandwidth calculation
        self._bytes: Deque[Tuple[float, int]] = deque()
        # Last alert time
        self._last_alert: Optional[float] = None
        self._alert_cooldown = 10.0
        self._baseline_min_packets = 50

    def observe(self, record: PacketRecord) -> Optional[ThreatAlert]:
        now = record.timestamp

        with self._lock:
            self._packets.append(now)
            self._bytes.append((now, record.size))

            window = self.config.traffic_spike_window_seconds
            cutoff = now - window

            while self._packets and self._packets[0] < cutoff:
                self._packets.popleft()
            while self._bytes and self._bytes[0][0] < cutoff:
                self._bytes.popleft()

            if len(self._packets) < self._baseline_min_packets:
                return None

            current_pps = len(self._packets) / window if window > 0 else 0

            # Calculate baseline from the earlier portion of the current window.
            baseline_packets = sum(1 for t in self._packets if t < now - window / 2)

            if baseline_packets < 10:
                return None

            baseline_pps = baseline_packets / (window / 2) if window > 0 else 0

            if baseline_pps < 1.0:
                baseline_pps = 1.0

            multiplier = current_pps / baseline_pps

            if multiplier < self.config.traffic_spike_multiplier:
                return None

            if self._last_alert is not None and now - self._last_alert < self._alert_cooldown:
                return None
            self._last_alert = now

            return ThreatAlert(
                timestamp=now,
                rule=self.rule_id,
                severity=Severity.MEDIUM,
                src_ip="0.0.0.0",  # Global traffic spike, not tied to specific IP
                dst_ip=None,
                detail=(
                    f"Traffic increased from baseline {baseline_pps:.1f} packets/sec "
                    f"to {current_pps:.1f} packets/sec ({multiplier:.1f}x increase)."
                ),
                evidence_count=int(current_pps),
            )

    def reset(self) -> None:
        with self._lock:
            self._packets.clear()
            self._bytes.clear()
            self._last_alert = None

    def cleanup_state(self, now: float) -> None:
        """Purge expired state entries."""
        with self._lock:
            window = self.config.traffic_spike_window_seconds * 2
            cutoff = now - window
            while self._packets and self._packets[0] < cutoff:
                self._packets.popleft()
            while self._bytes and self._bytes[0][0] < cutoff:
                self._bytes.popleft()
