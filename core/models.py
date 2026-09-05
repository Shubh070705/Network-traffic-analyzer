"""
core/models.py

Plain data structures shared across the pipeline. Keeping these as simple
dataclasses (no Scapy objects leak past the parser) keeps every downstream
stage — statistics, detection, dashboard, exporters — decoupled from the
capture library and easy to unit test with synthetic data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import time
from typing import Optional


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class PacketRecord:
    """
    Normalized, metadata-only view of a single captured packet.

    No payload bytes are stored here — only header-level metadata,
    which is all this tool needs and all it is designed to touch.
    """

    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: Protocol
    size: int
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None  # e.g. "S", "SA", "PA", ...
    ttl: Optional[int] = None

    def flow_key(self) -> tuple:
        """A directionless-ish key useful for grouping related traffic."""
        return (self.src_ip, self.dst_ip, self.protocol.value)


@dataclass
class ThreatAlert:
    """A single detection event raised by the detection engine."""

    timestamp: float
    rule: str  # e.g. "NET-001", "NET-002"
    severity: Severity
    src_ip: str
    dst_ip: Optional[str]
    detail: str
    evidence_count: int = 0
    risk_score: int = 0  # Risk score 0-100 calculated by risk scorer

    def as_row(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "type": "ALERT",
            "rule": self.rule,
            "severity": self.severity.value,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip or "",
            "detail": self.detail,
            "evidence_count": self.evidence_count,
            "risk_score": self.risk_score,
        }


@dataclass
class WatchlistEntry:
    """A host currently flagged as suspicious, kept for the dashboard."""

    ip: str
    last_seen: float
    highest_severity: Severity
    reasons: list[str] = field(default_factory=list)
    alert_count: int = 0
    highest_risk_score: int = 0  # Highest risk score seen from this IP


@dataclass
class StatsSnapshot:
    """Immutable snapshot of traffic statistics at a point in time."""

    generated_at: float
    total_packets: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float
    average_packet_size: float
    protocol_counts: dict
    protocol_ratios: dict
    top_hosts: list  # list[(ip, packet_count)]
    top_talkers: list  # list[(ip, byte_count)]

    @staticmethod
    def empty() -> "StatsSnapshot":
        return StatsSnapshot(
            generated_at=time(),
            total_packets=0,
            total_bytes=0,
            packets_per_second=0.0,
            bytes_per_second=0.0,
            average_packet_size=0.0,
            protocol_counts={p.value: 0 for p in Protocol},
            protocol_ratios={p.value: 0.0 for p in Protocol},
            top_hosts=[],
            top_talkers=[],
        )
