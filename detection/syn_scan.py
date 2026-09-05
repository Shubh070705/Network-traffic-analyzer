"""
detection/syn_scan.py

Heuristic SYN-scan detector.

A classic TCP SYN scan sends lone SYN packets (no completed handshake) to
many distinct destination ports from one source, usually in a short burst.
This detector tracks, per source IP, the set of distinct destination ports
that received a bare-SYN packet ("S" flags only, not "SA"/"PA"/etc.) within
a sliding time window. When the distinct-port count crosses the configured
threshold, it raises a SYN_SCAN alert.

This is a HEURISTIC. Legitimate software (some connection-pooling clients,
certain network scanners run by the user themselves, port-knocking tools)
can trigger it. Treat alerts as leads for investigation, not proof of an
attack.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from time import time
from typing import Deque, Dict, Optional, Set, Tuple

from config import DetectionConfig
from core.models import PacketRecord, Severity, ThreatAlert
from detection.base import BaseDetector

def _is_syn_only(tcp_flags: Optional[str]) -> bool:
    if not tcp_flags:
        return False
    flags = tcp_flags.strip()
    return "S" in flags and "A" not in flags


class SynScanDetector(BaseDetector):
    """TCP SYN scan detector - Rule NET-001."""

    rule_id = "NET-001"
    rule_name = "TCP SYN Scan"

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        # src_ip -> deque[(timestamp, dst_port)]
        self._events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        # src_ip -> last time an alert was raised, to avoid alert spam.
        # Absence of a key (not 0.0) means "never alerted", so a real alert
        # is never suppressed just because the session clock started near 0.
        self._last_alert: Dict[str, float] = {}
        self._alert_cooldown = 5.0

    def observe(self, record: PacketRecord) -> Optional[ThreatAlert]:
        if record.protocol.value != "TCP" or record.dst_port is None:
            return None
        if not _is_syn_only(record.tcp_flags):
            return None

        now = record.timestamp
        with self._lock:
            events = self._events[record.src_ip]
            events.append((now, record.dst_port))
            cutoff = now - self.config.syn_scan_window_seconds
            while events and events[0][0] < cutoff:
                events.popleft()

            distinct_ports: Set[int] = {port for _, port in events}
            count = len(distinct_ports)

            if count < self.config.syn_scan_port_threshold:
                return None

            last = self._last_alert.get(record.src_ip)
            if last is not None and now - last < self._alert_cooldown:
                return None
            self._last_alert[record.src_ip] = now

            severity = self._severity_for(count)
            return ThreatAlert(
                timestamp=now,
                rule=self.rule_id,
                severity=severity,
                src_ip=record.src_ip,
                dst_ip=None,
                detail=(
                    f"{record.src_ip} sent bare-SYN packets to {count} distinct "
                    f"ports within {self.config.syn_scan_window_seconds:.0f}s "
                    "(possible TCP SYN scan)."
                ),
                evidence_count=count,
            )

    def _severity_for(self, count: int) -> Severity:
        base = self.config.syn_scan_port_threshold
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
            cutoff = now - self.config.syn_scan_window_seconds
            for src_ip in list(self._events.keys()):
                events = self._events[src_ip]
                while events and events[0][0] < cutoff:
                    events.popleft()
                if not events:
                    del self._events[src_ip]
            expired = [ip for ip, ts in self._last_alert.items() if now - ts > self._alert_cooldown * 2]
            for ip in expired:
                del self._last_alert[ip]
