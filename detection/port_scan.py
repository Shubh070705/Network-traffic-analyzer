"""
detection/port_scan.py

Heuristic generic port-scan detector.

Tracks, per (source IP, destination IP) pair, the set of distinct
destination ports contacted (any protocol, any TCP flag combination) within
a sliding time window. This catches scan patterns broader than the
SYN-only case in detection/syn_scan.py — e.g. connect() scans that complete
the handshake, or UDP scans.

This is a HEURISTIC and can be triggered by legitimate multi-service
clients (e.g. a monitoring agent that health-checks many ports on one
host). Alerts should be treated as investigation leads.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Set, Tuple

from config import DetectionConfig
from core.models import PacketRecord, Severity, ThreatAlert
from detection.base import BaseDetector


class PortScanDetector(BaseDetector):
    """Port scan detector - Rule NET-002."""

    rule_id = "NET-002"
    rule_name = "Port Scan"

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        # (src_ip, dst_ip) -> deque[(timestamp, port)]
        self._events: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = defaultdict(deque)
        # Absence of a key (not 0.0) means "never alerted", so a real alert
        # is never suppressed just because the session clock started near 0.
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._alert_cooldown = 5.0

    def observe(self, record: PacketRecord) -> Optional[ThreatAlert]:
        if record.dst_port is None:
            return None

        key = (record.src_ip, record.dst_ip)
        now = record.timestamp

        with self._lock:
            events = self._events[key]
            events.append((now, record.dst_port))
            cutoff = now - self.config.port_scan_window_seconds
            while events and events[0][0] < cutoff:
                events.popleft()

            distinct_ports: Set[int] = {port for _, port in events}
            count = len(distinct_ports)

            if count < self.config.port_scan_port_threshold:
                return None

            last = self._last_alert.get(key)
            if last is not None and now - last < self._alert_cooldown:
                return None
            self._last_alert[key] = now

            severity = self._severity_for(count)
            return ThreatAlert(
                timestamp=now,
                rule=self.rule_id,
                severity=severity,
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                detail=(
                    f"{record.src_ip} contacted {count} distinct ports on "
                    f"{record.dst_ip} within {self.config.port_scan_window_seconds:.0f}s "
                    "(possible port scan)."
                ),
                evidence_count=count,
            )

    def _severity_for(self, count: int) -> Severity:
        base = self.config.port_scan_port_threshold
        if count >= base * self.config.high_multiplier:
            return Severity.HIGH
        if count >= base * self.config.medium_multiplier:
            return Severity.MEDIUM
        return Severity.LOW

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._last_alert.clear()

    def cleanup_state(self, now: float) -> None:
        """Purge expired state entries."""
        with self._lock:
            cutoff = now - self.config.port_scan_window_seconds
            for key in list(self._events.keys()):
                events = self._events[key]
                while events and events[0][0] < cutoff:
                    events.popleft()
                if not events:
                    del self._events[key]
            expired = [k for k, ts in self._last_alert.items() if now - ts > self._alert_cooldown * 2]
            for k in expired:
                del self._last_alert[k]
