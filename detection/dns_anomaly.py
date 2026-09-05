"""
detection/dns_anomaly.py

Heuristic DNS request anomaly detector.

Detects unusually high DNS request activity which may indicate DNS-based
attacks (DNS amplification, DNS tunneling, exfiltration attempts) or
misbehaving clients.

The detector tracks DNS requests (UDP/TCP port 53) per source IP and
globally within a sliding time window.

This is a HEURISTIC. Legitimate DNS-heavy applications (web browsers,
DNS servers, some monitoring tools) can trigger it. Alerts should be
treated as investigation leads.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from config import DetectionConfig
from core.models import PacketRecord, Severity, ThreatAlert
from detection.base import BaseDetector


class DnsAnomalyDetector(BaseDetector):
    """DNS Request Anomaly detector - Rule NET-006."""

    rule_id = "NET-006"
    rule_name = "DNS Request Anomaly"

    def __init__(self, config: DetectionConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        # src_ip -> deque of timestamps
        self._src_requests: Dict[str, Deque[float]] = defaultdict(deque)
        # Global request tracker
        self._global_requests: Deque[float] = deque()
        # Last alert times: src_ip or "global" -> timestamp
        self._last_alert: Dict[str, float] = {}
        self._alert_cooldown = 5.0

    def observe(self, record: PacketRecord) -> Optional[ThreatAlert]:
        # Detect DNS traffic (destination port 53)
        is_dns = False
        if record.protocol.value == "UDP" and record.dst_port == 53:
            is_dns = True
        elif record.protocol.value == "TCP" and record.dst_port == 53:
            is_dns = True

        if not is_dns:
            return None

        now = record.timestamp
        src_ip = record.src_ip

        with self._lock:
            # Track per source
            self._src_requests[src_ip].append(now)
            cutoff = now - self.config.dns_anomaly_window_seconds
            while self._src_requests[src_ip] and self._src_requests[src_ip][0] < cutoff:
                self._src_requests[src_ip].popleft()

            # Track globally
            self._global_requests.append(now)
            while self._global_requests and self._global_requests[0] < cutoff:
                self._global_requests.popleft()

            src_count = len(self._src_requests[src_ip])
            global_count = len(self._global_requests)

            threshold = self.config.dns_anomaly_request_threshold

            # Check per-source threshold
            if src_count >= threshold:
                last = self._last_alert.get(src_ip)
                if last is not None and now - last < self._alert_cooldown:
                    return None
                self._last_alert[src_ip] = now

                return ThreatAlert(
                    timestamp=now,
                    rule=self.rule_id,
                    severity=Severity.MEDIUM,
                    src_ip=src_ip,
                    dst_ip=None,
                    detail=(
                        f"{src_ip} sent {src_count} DNS requests within "
                        f"{self.config.dns_anomaly_window_seconds:.0f}s "
                        "(possible DNS anomaly)."
                    ),
                    evidence_count=src_count,
                )

            # Check global threshold (higher threshold for network-wide)
            global_threshold = threshold * 3
            if global_count >= global_threshold:
                last = self._last_alert.get("global")
                if last is not None and now - last < self._alert_cooldown:
                    return None
                self._last_alert["global"] = now

                return ThreatAlert(
                    timestamp=now,
                    rule=self.rule_id,
                    severity=Severity.MEDIUM,
                    src_ip="0.0.0.0",
                    dst_ip=None,
                    detail=(
                        f"Observed {global_count} DNS requests within "
                        f"{self.config.dns_anomaly_window_seconds:.0f}s "
                        "(network-wide DNS anomaly)."
                    ),
                    evidence_count=global_count,
                )

            return None

    def reset(self) -> None:
        with self._lock:
            self._src_requests.clear()
            self._global_requests.clear()
            self._last_alert.clear()

    def cleanup_state(self, now: float) -> None:
        """Purge expired state entries."""
        with self._lock:
            cutoff = now - self.config.dns_anomaly_window_seconds
            for src_ip in list(self._src_requests.keys()):
                events = self._src_requests[src_ip]
                while events and events[0] < cutoff:
                    events.popleft()
                if not events:
                    del self._src_requests[src_ip]
            while self._global_requests and self._global_requests[0] < cutoff:
                self._global_requests.popleft()
            expired = [k for k, ts in self._last_alert.items() if now - ts > self._alert_cooldown * 2]
            for k in expired:
                del self._last_alert[k]
