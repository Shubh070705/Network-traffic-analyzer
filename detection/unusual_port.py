"""
detection/unusual_port.py

Heuristic unusual port activity detector.

Detects potentially suspicious use of uncommon destination ports.
Uses conservative logic: not every uncommon port is suspicious.

The detector considers:
- Uncommon ports (not well-known system ports)
- Repeated connections to unusual ports
- Multiple unusual ports contacted on the same host

This is a HEURISTIC. Legitimate applications using non-standard ports
can trigger it. Alerts should be treated as investigation leads.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Set, Tuple

from config import DetectionConfig
from core.models import PacketRecord, Severity, ThreatAlert
from detection.base import BaseDetector


# Common well-known ports that should not trigger this detector
COMMON_PORTS = {
    # Standard services
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
    110, 119, 123, 143, 161, 162, 389, 443, 465, 514,
    587, 636, 993, 995,
    # Common alternative HTTP/HTTPS
    1080, 8080, 8443, 8888, 9000,
    # Database ports
    1433, 1434, 1521, 3306, 5432, 6379, 27017, 27018, 27019,
    # Remote access
    3389, 5900, 5901, 5902,
    # Other common
    2049, 1723,
}


class UnusualPortDetector(BaseDetector):
    """Unusual Port Activity detector - Rule NET-007."""

    rule_id = "NET-007"
    rule_name = "Unusual Port Activity"

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        # (src_ip, dst_ip) -> deque[(timestamp, dst_port)]
        self._events: Dict[Tuple[str, str], Deque[Tuple[float, int]]] = defaultdict(deque)
        self._last_alert: Dict[Tuple[str, str], float] = {}
        self._alert_cooldown = 5.0

    def observe(self, record: PacketRecord) -> Optional[ThreatAlert]:
        if record.dst_port is None:
            return None

        # Skip common ports
        if record.dst_port in COMMON_PORTS:
            return None

        # Skip high ephemeral ports as destinations (usually legitimate)
        if record.dst_port >= 49152:
            return None

        now = record.timestamp
        key = (record.src_ip, record.dst_ip)

        with self._lock:
            events = self._events[key]
            events.append((now, record.dst_port))
            cutoff = now - self.config.unusual_port_window_seconds
            while events and events[0][0] < cutoff:
                events.popleft()

            ports = [port for _, port in events]
            unique_unusual_ports: Set[int] = set(ports)
            threshold = self.config.unusual_port_threshold

            if len(ports) < threshold:
                return None
            if len(unique_unusual_ports) < threshold:
                return None

            last = self._last_alert.get(key)
            if last is not None and now - last < self._alert_cooldown:
                return None
            self._last_alert[key] = now

            return ThreatAlert(
                timestamp=now,
                rule=self.rule_id,
                severity=Severity.LOW,
                src_ip=record.src_ip,
                dst_ip=record.dst_ip,
                detail=(
                    f"{record.src_ip} contacted {len(unique_unusual_ports)} "
                    f"unusual ports on {record.dst_ip} within "
                    f"{self.config.unusual_port_window_seconds:.0f}s "
                    "(unusual port activity)."
                ),
                evidence_count=len(ports),
            )

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._last_alert.clear()

    def cleanup_state(self, now: float) -> None:
        """Purge expired state entries."""
        with self._lock:
            cutoff = now - self.config.unusual_port_window_seconds
            for key in list(self._events.keys()):
                events = self._events[key]
                while events and events[0][0] < cutoff:
                    events.popleft()
                if not events:
                    del self._events[key]
            expired = [k for k, ts in self._last_alert.items() if now - ts > self._alert_cooldown * 2]
            for k in expired:
                del self._last_alert[k]
