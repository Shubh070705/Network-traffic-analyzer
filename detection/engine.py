"""
detection/engine.py

Coordinates heuristic detectors and maintains the watchlist shown on the
dashboard. Also holds the recent-alerts log used for CSV export.

DETECTION RULES ARE HEURISTICS. They flag traffic *patterns* consistent
with suspicious behavior; they do not prove malicious intent, and they can
and will produce false positives. Always investigate before acting on
an alert.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Callable, Deque, Dict, List, Optional

from config import DetectionConfig
from core.models import PacketRecord, Severity, ThreatAlert, WatchlistEntry
from detection.base import BaseDetector
from detection.dns_anomaly import DnsAnomalyDetector
from detection.icmp_sweep import IcmpSweepDetector
from detection.port_scan import PortScanDetector
from detection.risk import RiskScorer
from detection.syn_flood import SynFloodDetector
from detection.syn_scan import SynScanDetector
from detection.traffic_spike import TrafficSpikeDetector
from detection.unusual_port import UnusualPortDetector
from incident import Incident, IncidentCorrelator

_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}

# How often to run cleanup_state (every N packets)
_CLEANUP_INTERVAL = 500


class DetectionEngine:
    """
    Coordinates all heuristic detectors.

    Maintains a list of detectors and distributes packet observations to each.
    Aggregates alerts into a watchlist and recent-alerts log.
    """

    def __init__(
        self,
        config: DetectionConfig,
        on_alert: Optional[Callable[[ThreatAlert], None]] = None,
        alert_log_maxlen: int = 500,
    ) -> None:
        self.config = config
        self.on_alert = on_alert

        # Initialize all detectors
        self.detectors: List[BaseDetector] = [
            SynScanDetector(config),
            PortScanDetector(config),
            IcmpSweepDetector(config),
            SynFloodDetector(config),
            TrafficSpikeDetector(config),
            DnsAnomalyDetector(config),
            UnusualPortDetector(config),
        ]

        # Initialize risk scoring engine
        self._risk_scorer = RiskScorer()

        self._lock = threading.Lock()
        self._watchlist: Dict[str, WatchlistEntry] = {}
        self._alert_log: Deque[ThreatAlert] = deque(maxlen=alert_log_maxlen)
        self._incidents = IncidentCorrelator(
            correlation_window_seconds=config.watchlist_ttl_seconds,
            max_incidents=alert_log_maxlen,
        )
        self._packet_count = 0

    def register_detector(self, detector: BaseDetector) -> None:
        """Add a new detector to the engine."""
        with self._lock:
            self.detectors.append(detector)

    def observe(self, record: PacketRecord) -> List[ThreatAlert]:
        """
        Process a packet through all detectors and collect alerts.

        Also performs periodic cleanup of detector state.
        Each alert is scored by the risk engine before being recorded and exposed.
        """
        raw_alerts: List[ThreatAlert] = []

        # Run all detectors
        for detector in self.detectors:
            try:
                alert = detector.observe(record)
                if alert:
                    raw_alerts.append(alert)
            except Exception:  # noqa: BLE001
                # Keep one detector failure from stopping the whole pipeline.
                pass

        # Apply risk scoring to all alerts
        alerts: List[ThreatAlert] = []
        for alert in raw_alerts:
            scored_alert = self._risk_scorer.score_alert(alert)
            alerts.append(scored_alert)

        # Record alerts
        for alert in alerts:
            self._record_alert(alert)
            self._incidents.observe(alert)
            if self.on_alert:
                try:
                    self.on_alert(alert)
                except Exception:  # noqa: BLE001
                    pass

        # Periodic cleanup
        self._packet_count += 1
        if self._packet_count % _CLEANUP_INTERVAL == 0:
            self._cleanup_detectors(record.timestamp)

        self._expire_watchlist(record.timestamp)
        return alerts

    def _record_alert(self, alert: ThreatAlert) -> None:
        with self._lock:
            self._alert_log.append(alert)
            entry = self._watchlist.get(alert.src_ip)
            if entry is None:
                entry = WatchlistEntry(
                    ip=alert.src_ip,
                    last_seen=alert.timestamp,
                    highest_severity=alert.severity,
                    reasons=[alert.rule],
                    alert_count=1,
                    highest_risk_score=alert.risk_score,
                )
            else:
                entry.last_seen = alert.timestamp
                entry.alert_count += 1
                if alert.rule not in entry.reasons:
                    entry.reasons.append(alert.rule)
                if _SEVERITY_RANK[alert.severity] > _SEVERITY_RANK[entry.highest_severity]:
                    entry.highest_severity = alert.severity
                if alert.risk_score > entry.highest_risk_score:
                    entry.highest_risk_score = alert.risk_score
            self._watchlist[alert.src_ip] = entry

    def _expire_watchlist(self, now: float) -> None:
        ttl = self.config.watchlist_ttl_seconds
        with self._lock:
            expired = [ip for ip, e in self._watchlist.items() if now - e.last_seen > ttl]
            for ip in expired:
                del self._watchlist[ip]

    def _cleanup_detectors(self, now: float) -> None:
        """Run cleanup_state on all detectors."""
        for detector in self.detectors:
            try:
                detector.cleanup_state(now)
            except Exception:  # noqa: BLE001
                pass

    def watchlist_snapshot(self) -> List[WatchlistEntry]:
        with self._lock:
            entries = list(self._watchlist.values())
        entries.sort(key=lambda e: (_SEVERITY_RANK[e.highest_severity], e.last_seen), reverse=True)
        return entries

    def recent_alerts(self, limit: int = 50) -> List[ThreatAlert]:
        with self._lock:
            items = list(self._alert_log)
        return items[-limit:]

    def incidents_snapshot(self, limit: int = 20) -> List[Incident]:
        return self._incidents.snapshot(limit=limit)

    def reset(self) -> None:
        """Reset all detectors and clear watchlist/alert log."""
        for detector in self.detectors:
            try:
                detector.reset()
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            self._watchlist.clear()
            self._alert_log.clear()
            self._packet_count = 0
        self._incidents.reset()
