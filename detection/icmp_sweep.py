"""
detection/icmp_sweep.py

Heuristic ICMP sweep (host discovery) detector.

Detects when one source sends ICMP traffic to many distinct destination IPs
within a sliding time window. This pattern can show up during host discovery
and other broad network probing.

This is a HEURISTIC. Legitimate tools (monitoring agents, network scanners
run by the user, some load balancers) can trigger it. Alerts should be
treated as investigation leads, not proof of an attack.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Deque, Dict, Optional, Set, Tuple

from config import DetectionConfig
from core.models import PacketRecord, Severity, ThreatAlert
from detection.base import BaseDetector


class IcmpSweepDetector(BaseDetector):
    """ICMP Sweep detector - Rule NET-003."""

    rule_id = "NET-003"
    rule_name = "ICMP Sweep"

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        # src_ip -> deque[(timestamp, dst_ip)]
        self._events: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        # src_ip -> last alert time
        self._last_alert: Dict[str, float] = {}
        self._alert_cooldown = 5.0

    def observe(self, record: PacketRecord) -> Optional[ThreatAlert]:
        if record.protocol.value != "ICMP":
            return None

        now = record.timestamp
        with self._lock:
            events = self._events[record.src_ip]
            events.append((now, record.dst_ip))
            cutoff = now - self.config.icmp_sweep_window_seconds
            while events and events[0][0] < cutoff:
                events.popleft()

            distinct_hosts: Set[str] = {ip for _, ip in events}
            count = len(distinct_hosts)

            if count < self.config.icmp_sweep_host_threshold:
                return None

            last = self._last_alert.get(record.src_ip)
            if last is not None and now - last < self._alert_cooldown:
                return None
            self._last_alert[record.src_ip] = now

            return ThreatAlert(
                timestamp=now,
                rule=self.rule_id,
                severity=Severity.MEDIUM,
                src_ip=record.src_ip,
                dst_ip=None,
                detail=(
                    f"{record.src_ip} sent ICMP traffic to {count} "
                    f"distinct hosts within {self.config.icmp_sweep_window_seconds:.0f}s "
                    "(possible ICMP sweep / host discovery)."
                ),
                evidence_count=count,
            )

    def reset(self) -> None:
        with self._lock:
            self._events.clear()
            self._last_alert.clear()

    def cleanup_state(self, now: float) -> None:
        """Purge expired state entries."""
        with self._lock:
            cutoff = now - self.config.icmp_sweep_window_seconds
            for src_ip in list(self._events.keys()):
                events = self._events[src_ip]
                while events and events[0][0] < cutoff:
                    events.popleft()
                if not events:
                    del self._events[src_ip]
            expired = [ip for ip, ts in self._last_alert.items() if now - ts > self._alert_cooldown * 2]
            for ip in expired:
                del self._last_alert[ip]
