from __future__ import annotations

import threading
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from core.models import ThreatAlert
from incident.model import Incident, IncidentStatus


class IncidentCorrelator:
    """Groups related alerts into bounded incident history."""

    def __init__(
        self,
        correlation_window_seconds: float = 300.0,
        max_incidents: int = 100,
    ) -> None:
        self.correlation_window_seconds = correlation_window_seconds
        self.max_incidents = max(1, max_incidents)
        self._lock = threading.Lock()
        self._next_id = 1
        self._incidents: Dict[str, Incident] = {}
        self._order: Deque[str] = deque()
        self._active_by_key: Dict[Tuple[str, Optional[str]], str] = {}

    def observe(self, alert: ThreatAlert) -> Incident:
        key = self._key_for(alert)
        with self._lock:
            self._expire_old(alert.timestamp)
            incident = self._get_active_incident(key, alert)
            incident.add_alert(alert)
            self._incidents[incident.incident_id] = incident
            self._active_by_key[key] = incident.incident_id
            self._enforce_limit()
            return incident

    def snapshot(self, limit: int = 20) -> List[Incident]:
        with self._lock:
            items = [self._incidents[incident_id] for incident_id in self._order]
        items.sort(key=lambda incident: incident.last_seen, reverse=True)
        return items[:limit]

    def reset(self) -> None:
        with self._lock:
            self._next_id = 1
            self._incidents.clear()
            self._order.clear()
            self._active_by_key.clear()

    def _get_active_incident(
        self,
        key: Tuple[str, Optional[str]],
        alert: ThreatAlert,
    ) -> Incident:
        incident_id = self._active_by_key.get(key)
        if incident_id is not None:
            incident = self._incidents.get(incident_id)
            if incident and alert.timestamp - incident.last_seen <= self.correlation_window_seconds:
                return incident

        incident = Incident(
            incident_id=f"INC-{self._next_id:04d}",
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            first_seen=alert.timestamp,
            last_seen=alert.timestamp,
        )
        self._next_id += 1
        self._order.append(incident.incident_id)
        return incident

    def _expire_old(self, now: float) -> None:
        cutoff = now - self.correlation_window_seconds
        for key, incident_id in list(self._active_by_key.items()):
            incident = self._incidents.get(incident_id)
            if incident is None or incident.last_seen < cutoff:
                if incident is not None:
                    incident.status = IncidentStatus.EXPIRED
                del self._active_by_key[key]

    def _enforce_limit(self) -> None:
        while len(self._order) > self.max_incidents:
            old_id = self._order.popleft()
            old = self._incidents.pop(old_id, None)
            if old is not None:
                old_key = (old.src_ip, old.dst_ip)
                if self._active_by_key.get(old_key) == old_id:
                    del self._active_by_key[old_key]

    @staticmethod
    def _key_for(alert: ThreatAlert) -> Tuple[str, Optional[str]]:
        return (alert.src_ip, alert.dst_ip)
