"""Filtering state and helpers for the live dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, List, Optional, Sequence

from core.models import PacketRecord, Protocol, Severity, ThreatAlert, WatchlistEntry
from incident import Incident


ALL = "ALL"
RULE_ALIASES = {
    "SYN_SCAN": "NET-001",
    "TCP_SYN_SCAN": "NET-001",
    "PORT_SCAN": "NET-002",
    "ICMP_SWEEP": "NET-003",
    "SYN_FLOOD": "NET-004",
    "TRAFFIC_SPIKE": "NET-005",
    "DNS_ANOMALY": "NET-006",
    "DNS_REQUEST_ANOMALY": "NET-006",
    "UNUSUAL_PORT": "NET-007",
    "UNUSUAL_PORT_ACTIVITY": "NET-007",
}


class FilterMode(str, Enum):
    ALL = "ALL"
    THREATS = "THREATS"
    TCP = "TCP"
    UDP = "UDP"
    HOSTS = "HOSTS"


@dataclass
class DashboardFilterState:
    """Current dashboard view/filter settings."""

    mode: FilterMode = FilterMode.ALL
    protocol: str = ALL
    severity: str = ALL
    host: str = ALL
    rule: str = ALL
    search: str = ALL
    search_active: bool = False
    quit_requested: bool = False

    def __post_init__(self) -> None:
        mode = self.mode
        protocol = self.protocol
        severity = self.severity
        host = self.host
        rule = self.rule
        search = self.search
        self.set_mode(mode)
        self.set_protocol(protocol)
        self.set_severity(severity)
        self.set_host(host)
        self.set_rule(rule)
        self.set_search(search)

    def apply_shortcut(self, key: str) -> None:
        if self.search_active:
            self.apply_search_input(key)
            return

        key = key.lower()
        if key == "1":
            self.set_mode(FilterMode.ALL)
        elif key == "2":
            self.set_mode(FilterMode.THREATS)
        elif key == "3":
            self.set_mode(FilterMode.TCP)
        elif key == "4":
            self.set_mode(FilterMode.UDP)
        elif key == "5":
            self.set_mode(FilterMode.HOSTS)
        elif key == "/":
            self.start_search()
        elif key == "\x1b":
            self.clear_search()
        elif key == "q":
            self.quit_requested = True

    def start_search(self) -> None:
        self.search_active = True
        if self.search == ALL:
            self.search = ""

    def apply_search_input(self, key: str) -> None:
        if key in ("\x1b",):
            self.clear_search()
            self.search_active = False
            return
        if key in ("\r", "\n"):
            self.search_active = False
            if not self.search.strip():
                self.search = ALL
            return
        if key in ("\x7f", "\b"):
            self.search = self.search[:-1]
            if not self.search:
                self.search = ""
            return
        if len(key) == 1 and key.isprintable():
            if self.search == ALL:
                self.search = ""
            self.search += key

    def set_search(self, value: Optional[str]) -> None:
        raw = "" if value is None else str(value).strip()
        self.search = raw if raw else ALL

    def clear_search(self) -> None:
        self.search = ALL

    @property
    def has_search(self) -> bool:
        return self.search != ALL and bool(self.search.strip())

    def set_mode(self, mode: FilterMode | str) -> None:
        raw = mode.value if isinstance(mode, FilterMode) else str(mode)
        try:
            self.mode = FilterMode(raw.upper())
        except ValueError:
            return
        if self.mode == FilterMode.ALL:
            self.reset_filters()
        elif self.mode == FilterMode.THREATS:
            self.protocol = ALL
        elif self.mode == FilterMode.HOSTS:
            self.protocol = ALL
        elif self.mode in (FilterMode.TCP, FilterMode.UDP):
            self.protocol = self.mode.value

    def reset_filters(self) -> None:
        self.protocol = ALL
        self.severity = ALL
        self.host = ALL
        self.rule = ALL

    def set_protocol(self, value: Optional[str]) -> None:
        normalized = _normalize(value)
        if normalized == ALL or normalized in {p.value for p in Protocol}:
            self.protocol = normalized

    def set_severity(self, value: Optional[str]) -> None:
        normalized = _normalize(value)
        if normalized == ALL or normalized in {s.value for s in Severity}:
            self.severity = normalized

    def set_host(self, value: Optional[str]) -> None:
        normalized = _normalize(value)
        if normalized:
            self.host = normalized

    def set_rule(self, value: Optional[str]) -> None:
        normalized = _normalize(value)
        if normalized:
            self.rule = RULE_ALIASES.get(normalized, normalized)


@dataclass(frozen=True)
class HostActivity:
    ip: str
    packets: int = 0
    risk_score: int = 0
    alert_count: int = 0
    severity: Severity = Severity.LOW


def filter_records(
    records: Sequence[PacketRecord],
    state: DashboardFilterState,
    alerts: Sequence[ThreatAlert] = (),
    watchlist: Sequence[WatchlistEntry] = (),
) -> List[PacketRecord]:
    threat_hosts = _threat_hosts(alerts, watchlist)
    filtered = []
    for record in records:
        if state.mode == FilterMode.THREATS and not _record_matches_hosts(record, threat_hosts):
            continue
        if not _record_matches_protocol(record, state.protocol):
            continue
        if not _record_matches_host(record, state.host):
            continue
        if not _matches_search(record_search_values(record), state.search):
            continue
        filtered.append(record)
    return filtered


def filter_alerts(alerts: Sequence[ThreatAlert], state: DashboardFilterState) -> List[ThreatAlert]:
    filtered = []
    for alert in alerts:
        if not _alert_matches_severity(alert, state.severity):
            continue
        if not _alert_matches_host(alert, state.host):
            continue
        if not _alert_matches_rule(alert, state.rule):
            continue
        if not _matches_search(alert_search_values(alert), state.search):
            continue
        filtered.append(alert)
    return filtered


def filter_watchlist(
    watchlist: Sequence[WatchlistEntry],
    state: DashboardFilterState,
) -> List[WatchlistEntry]:
    filtered = []
    for entry in watchlist:
        if state.host != ALL and entry.ip != state.host:
            continue
        if state.severity != ALL and entry.highest_severity.value != state.severity:
            continue
        if not _rule_in_values(state.rule, entry.reasons):
            continue
        if not _matches_search(watchlist_search_values(entry), state.search):
            continue
        filtered.append(entry)
    return filtered


def filter_incidents(incidents: Sequence[Incident], state: DashboardFilterState) -> List[Incident]:
    filtered = []
    for incident in incidents:
        if state.host != ALL and incident.src_ip != state.host and incident.dst_ip != state.host:
            continue
        if state.severity != ALL and incident.severity.value != state.severity:
            continue
        if not _rule_in_values(state.rule, incident.rules):
            continue
        if not _matches_search(incident_search_values(incident), state.search):
            continue
        filtered.append(incident)
    return filtered


def build_host_activity(
    top_hosts: Iterable[tuple[str, int]],
    watchlist: Sequence[WatchlistEntry],
    alerts: Sequence[ThreatAlert],
) -> List[HostActivity]:
    packet_counts = dict(top_hosts)
    entries = {entry.ip: entry for entry in watchlist}
    hosts = set(packet_counts) | set(entries)
    for alert in alerts:
        hosts.add(alert.src_ip)
        if alert.dst_ip:
            hosts.add(alert.dst_ip)

    rows = []
    for ip in hosts:
        entry = entries.get(ip)
        rows.append(
            HostActivity(
                ip=ip,
                packets=packet_counts.get(ip, 0),
                risk_score=entry.highest_risk_score if entry else 0,
                alert_count=entry.alert_count if entry else sum(1 for alert in alerts if alert.src_ip == ip),
                severity=entry.highest_severity if entry else Severity.LOW,
            )
        )
    rows.sort(key=lambda item: (item.risk_score, item.alert_count, item.packets), reverse=True)
    return rows


def filter_host_activity(rows: Sequence[HostActivity], state: DashboardFilterState) -> List[HostActivity]:
    filtered = []
    for row in rows:
        if state.host != ALL and row.ip != state.host:
            continue
        if state.severity != ALL and row.severity.value != state.severity:
            continue
        if not _matches_search(host_activity_search_values(row), state.search):
            continue
        filtered.append(row)
    return filtered


def _normalize(value: Optional[str]) -> str:
    if value is None:
        return ALL
    normalized = str(value).strip()
    return normalized.upper() if normalized else ALL


def record_search_values(record: PacketRecord) -> Iterable[object]:
    return (
        record.src_ip,
        record.dst_ip,
        record.protocol.value,
        record.src_port,
        record.dst_port,
        record.tcp_flags,
        record.ttl,
    )


def alert_search_values(alert: ThreatAlert) -> Iterable[object]:
    return (
        alert.src_ip,
        alert.dst_ip,
        alert.rule,
        _rule_alias_for(alert.rule),
        alert.severity.value,
        alert.detail,
        alert.evidence_count,
        alert.risk_score,
    )


def watchlist_search_values(entry: WatchlistEntry) -> Iterable[object]:
    return (
        entry.ip,
        entry.highest_severity.value,
        entry.highest_risk_score,
        entry.alert_count,
        *entry.reasons,
        *(_rule_alias_for(reason) for reason in entry.reasons),
    )


def incident_search_values(incident: Incident) -> Iterable[object]:
    return (
        incident.incident_id,
        incident.src_ip,
        incident.dst_ip,
        incident.severity.value,
        incident.risk_score,
        incident.alert_count,
        incident.status.value,
        *incident.rules,
        *(_rule_alias_for(rule) for rule in incident.rules),
        *incident.evidence,
    )


def host_activity_search_values(row: HostActivity) -> Iterable[object]:
    return (
        row.ip,
        row.severity.value,
        row.risk_score,
        row.alert_count,
        row.packets,
    )


def _matches_search(values: Iterable[object], search: str) -> bool:
    if search == ALL or not search.strip():
        return True
    needle = search.casefold()
    return any(needle in str(value).casefold() for value in values if value is not None)


def _rule_alias_for(rule: str) -> str:
    for alias, normalized in RULE_ALIASES.items():
        if normalized == rule:
            return alias
    return ""


def _record_matches_protocol(record: PacketRecord, protocol: str) -> bool:
    return protocol == ALL or record.protocol.value == protocol


def _record_matches_host(record: PacketRecord, host: str) -> bool:
    return host == ALL or record.src_ip == host or record.dst_ip == host


def _record_matches_hosts(record: PacketRecord, hosts: set[str]) -> bool:
    return bool(hosts) and (record.src_ip in hosts or record.dst_ip in hosts)


def _alert_matches_severity(alert: ThreatAlert, severity: str) -> bool:
    return severity == ALL or alert.severity.value == severity


def _alert_matches_host(alert: ThreatAlert, host: str) -> bool:
    return host == ALL or alert.src_ip == host or alert.dst_ip == host


def _alert_matches_rule(alert: ThreatAlert, rule: str) -> bool:
    normalized = RULE_ALIASES.get(rule, rule)
    return normalized == ALL or alert.rule == normalized


def _rule_in_values(rule: str, values: Iterable[str]) -> bool:
    normalized = RULE_ALIASES.get(rule, rule)
    return normalized == ALL or normalized in values


def _threat_hosts(alerts: Sequence[ThreatAlert], watchlist: Sequence[WatchlistEntry]) -> set[str]:
    hosts = {entry.ip for entry in watchlist}
    for alert in alerts:
        hosts.add(alert.src_ip)
        if alert.dst_ip:
            hosts.add(alert.dst_ip)
    return hosts
