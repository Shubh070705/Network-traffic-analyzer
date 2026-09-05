from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from core.models import Severity, ThreatAlert


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    UPDATED = "UPDATED"
    EXPIRED = "EXPIRED"


@dataclass
class Incident:
    """Related alerts grouped for quick investigation."""

    incident_id: str
    src_ip: str
    dst_ip: Optional[str]
    first_seen: float
    last_seen: float
    status: IncidentStatus = IncidentStatus.OPEN
    severity: Severity = Severity.LOW
    risk_score: int = 0
    alert_count: int = 0
    rules: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)

    def add_alert(self, alert: ThreatAlert, evidence_limit: int = 8) -> None:
        self.last_seen = alert.timestamp
        self.status = IncidentStatus.UPDATED if self.alert_count else IncidentStatus.OPEN
        self.alert_count += 1
        self.rules.add(alert.rule)
        if alert.risk_score > self.risk_score:
            self.risk_score = alert.risk_score
            self.severity = alert.severity
        elif _severity_rank(alert.severity) > _severity_rank(self.severity):
            self.severity = alert.severity
        if alert.detail and alert.detail not in self.evidence:
            self.evidence.append(alert.detail)
            if len(self.evidence) > evidence_limit:
                self.evidence = self.evidence[-evidence_limit:]


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.LOW: 0,
        Severity.MEDIUM: 1,
        Severity.HIGH: 2,
        Severity.CRITICAL: 3,
    }[severity]
