"""Risk scoring for NETWORK ANALYZER alerts.

Provides deterministic, explainable risk scores for security alerts based on
observable behavior and evidence. The risk score is a heuristic prioritization
mechanism and is NOT a probability of compromise.

Risk Score Ranges:
    0-29   LOW
    30-59  MEDIUM
    60-79  HIGH
    80-100 CRITICAL

The scoring system considers:
    - Detection type (base score)
    - Evidence magnitude (unique ports / unique hosts / event count)
    - Event intensity (rate multiplier for traffic spikes)
    - Multiple different detection rules triggered by the same source

Scores are capped at 100 and floored at 0. They are heuristic prioritization
helps, not a probability of compromise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple

from core.models import Severity, ThreatAlert


# --------------------------------------------------------------------------- #
# Severity boundary thresholds
# --------------------------------------------------------------------------- #

RISK_LOW_MAX = 29
RISK_MEDIUM_MAX = 59
RISK_HIGH_MAX = 79
RISK_CRITICAL_MAX = 100

# --------------------------------------------------------------------------- #
# Base scores per detection rule
# --------------------------------------------------------------------------- #
# The base represents the inherent concern of the detection type when observed
# at its minimum triggering threshold. Evidence bonuses raise the score from
# there. Scores are heuristic, not ground truth.
RULE_BASE_SCORES: Dict[str, int] = {
    "NET-001": 35,  # TCP SYN scan - active recon
    "NET-002": 40,  # Port scan - active recon on a single target
    "NET-003": 30,  # ICMP sweep - host discovery / recon
    "NET-004": 55,  # Possible SYN flood / abnormal SYN activity
    "NET-005": 25,  # Traffic spike - anomalous but many benign causes
    "NET-006": 30,  # DNS anomaly - possible tunnel / exfil
    "NET-007": 20,  # Unusual port activity - low-confidence lead
}

# Bonus tiers for high unique ports/reaches (port/host based rules).
_HIGH_EVIDENCE_TIERS: Tuple[Tuple[float, int], ...] = (
    (50, 15),
    (35, 10),
    (20, 5),
)
# Event-count bonus tiers for flood/anomaly rules.
_EVENT_EVIDENCE_TIERS: Tuple[Tuple[float, int], ...] = (
    (800, 20),
    (500, 15),
    (250, 10),
    (100, 5),
)
# Rate-multiplier bonus tiers for traffic spikes.
_RATE_EVIDENCE_TIERS: Tuple[Tuple[float, int], ...] = (
    (12.0, 15),
    (8.0, 10),
    (5.0, 5),
)
# Event-count bonus tiers for traffic spikes (approx PPS).
_SPIKE_EVENT_TIERS: Tuple[Tuple[float, int], ...] = (
    (500, 10),
    (300, 5),
)
# Unusual-port count bonus tiers.
_UNUSUAL_PORT_TIERS: Tuple[Tuple[float, int], ...] = (
    (20, 10),
    (10, 5),
)

# How long (seconds) we remember which rules a source has triggered, so the
# multi-rule bonus is only applied within a relevant window and tracking state
# stays bounded. Mirrors the watchlist default TTL.
RULE_TRACKING_WINDOW_SECONDS = 300.0

# Bonus per additional rule type (on top of the first), capped.
MULTI_RULE_BONUS_PER_RULE = 5
MULTI_RULE_BONUS_MAX = 15


@dataclass
class RiskFactors:
    """
    Evidence factors that contribute to the risk score.

    Only fields relevant to a rule are used; the rest default to 0.
    """

    unique_ports: int = 0
    unique_hosts: int = 0
    event_count: int = 0
    time_window_seconds: float = 0.0
    rate_multiplier: float = 1.0


def score_to_severity(score: int) -> Severity:
    """Convert a risk score (0-100) to a severity level."""
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 30:
        return Severity.MEDIUM
    return Severity.LOW


def clamp_score(score: int) -> int:
    """Clamp a raw score to the valid 0-100 range (never negative, never > 100)."""
    return max(0, min(100, score))


class RiskScorer:
    """
    Assigns a 0-100 heuristic risk score to alerts.

    Methodology:
        1. Start from the rule's base score.
        2. Add a bonus for evidence magnitude above scale (unique ports/hosts,
           event counts, rate-multipliers).
        3. Add a small bonus when the same source has triggered multiple
           different rule types within the tracking window.
        4. Clamp to 0-100.

    Bonus tiers are designed so a single rule alone can reach MEDIUM/HIGH on
    strong evidence, but CRITICAL is only reached by the strongest evidence
    and/or multiple coordinated detections from one source. Evidence is never
    double-counted: the scorer uses one bonus dimension per rule (see
    ``_factors_from_alert``).
    """

    def __init__(self) -> None:
        # src_ip -> (set of rule ids triggered, last seen timestamp)
        self._source_rules: Dict[str, Tuple[Set[str], float]] = {}

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def calculate_score(
        self,
        alert: ThreatAlert,
        factors: Optional[RiskFactors] = None,
    ) -> int:
        """Return the deterministic risk score (0-100) for an alert."""
        base = RULE_BASE_SCORES.get(alert.rule, 25)
        if factors is None:
            factors = self._factors_from_alert(alert)

        self._track_rule_for_source(alert.src_ip, alert.rule, alert.timestamp)
        multi_rule_count = self.get_source_rule_count(alert.src_ip)

        score = base
        score += self._factor_bonus(factors, alert.rule)
        if multi_rule_count > 1:
            score += min(
                MULTI_RULE_BONUS_MAX,
                (multi_rule_count - 1) * MULTI_RULE_BONUS_PER_RULE,
            )
        return clamp_score(score)

    def score_alert(
        self,
        alert: ThreatAlert,
        factors: Optional[RiskFactors] = None,
    ) -> ThreatAlert:
        """
        Score an alert and return a new alert with risk_score set and severity
        derived from the risk score (the risk score is the source of truth).
        """
        risk_score = self.calculate_score(alert, factors)
        severity = score_to_severity(risk_score)
        return ThreatAlert(
            timestamp=alert.timestamp,
            rule=alert.rule,
            severity=severity,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            detail=alert.detail,
            evidence_count=alert.evidence_count,
            risk_score=risk_score,
        )

    def reset(self) -> None:
        """Forget all multi-rule tracking state."""
        self._source_rules.clear()

    def cleanup_state(self, now: float) -> None:
        """Drop multi-rule tracking for sources idle longer than the window."""
        cutoff = now - RULE_TRACKING_WINDOW_SECONDS
        stale = [ip for ip, (_, last) in self._source_rules.items() if last < cutoff]
        for ip in stale:
            del self._source_rules[ip]

    def get_source_rule_count(self, src_ip: str) -> int:
        """Number of different rule types a source has triggered."""
        entry = self._source_rules.get(src_ip)
        return len(entry[0]) if entry else 0

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _track_rule_for_source(self, src_ip: str, rule: str, now: float) -> None:
        entry = self._source_rules.get(src_ip)
        if entry is None:
            self._source_rules[src_ip] = ({rule}, now)
        else:
            rules, _ = entry
            self._source_rules[src_ip] = (rules | {rule}, now)

    def _factors_from_alert(self, alert: ThreatAlert) -> RiskFactors:
        """Map an alert's evidence_count into the factor dimension used per rule."""
        evidence = max(0, alert.evidence_count)
        factors = RiskFactors(event_count=evidence, time_window_seconds=0.0)
        if alert.rule in ("NET-001", "NET-002", "NET-007"):
            factors.unique_ports = evidence
        elif alert.rule == "NET-003":
            factors.unique_hosts = evidence
        return factors

    def _factor_bonus(self, factors: RiskFactors, rule: str) -> int:
        """Single-dimension evidence bonus per rule; never double-counts."""
        if rule in ("NET-001", "NET-002"):
            return _scale_bonus(factors.unique_ports, _HIGH_EVIDENCE_TIERS)
        if rule == "NET-003":
            return _scale_bonus(factors.unique_hosts, _HIGH_EVIDENCE_TIERS)
        if rule == "NET-004":
            return _scale_bonus(factors.event_count, _EVENT_EVIDENCE_TIERS)
        if rule == "NET-005":
            rate_bonus = _scale_bonus(factors.rate_multiplier, _RATE_EVIDENCE_TIERS)
            event_bonus = _scale_bonus(factors.event_count, _SPIKE_EVENT_TIERS)
            return max(rate_bonus, event_bonus)
        if rule == "NET-006":
            return _scale_bonus(factors.event_count, _EVENT_EVIDENCE_TIERS)
        if rule == "NET-007":
            return _scale_bonus(factors.unique_ports, _UNUSUAL_PORT_TIERS)
        return 0


def _scale_bonus(value: float, tiers: Tuple[Tuple[float, int], ...]) -> int:
    """Look up the bonus associated with the highest tier the value meets."""
    for threshold, bonus in tiers:
        if value >= threshold:
            return bonus
    return 0


def explain_score(alert: ThreatAlert) -> str:
    """Human-readable explanation of a scored alert's risk score."""
    risk_score = getattr(alert, "risk_score", None)
    if risk_score is None:
        return "Risk score not calculated."
    base = RULE_BASE_SCORES.get(alert.rule, 25)
    severity = score_to_severity(alert.risk_score)
    lines = [
        f"Risk Score: {alert.risk_score}/100",
        f"Severity: {severity.value}",
        "",
        "Scoring breakdown:",
        f"  Base score for {alert.rule}: {base}",
        f"  Evidence count: {alert.evidence_count}",
    ]
    bonus = alert.risk_score - base
    if bonus > 0:
        lines.append(f"  Evidence/multi-rule bonuses: +{bonus}")
    lines.append("")
    lines.append(
        "Note: This is a heuristic score for prioritization, not a probability "
        "of compromise."
    )
    return "\n".join(lines)
